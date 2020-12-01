// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"github.com/edgelesssys/marblerun/test"
	"github.com/edgelesssys/marblerun/util"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestActivate(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// parse manifest
	var manifest Manifest
	require.NoError(json.Unmarshal([]byte(test.ManifestJSON), &manifest))

	// setup mock zaplogger which can be passed to Core
	zapLogger, err := zap.NewDevelopment()
	require.NoError(err)
	defer zapLogger.Sync()

	// create core
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &MockSealer{}
	coreServer, err := NewCore([]string{"localhost"}, validator, issuer, sealer, zapLogger)
	require.NoError(err)
	require.NotNil(coreServer)

	spawner := marbleSpawner{
		assert:     assert,
		issuer:     issuer,
		validator:  validator,
		manifest:   manifest,
		coreServer: coreServer,
	}

	// try to activate first backend marble prematurely before manifest is set
	spawner.newMarble("backend_first", "Azure", false)

	// set manifest
	_, err = coreServer.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	require.NoError(err)

	// activate first backend
	spawner.newMarble("backend_first", "Azure", true)

	// try to activate another first backend
	spawner.newMarble("backend_first", "Azure", false)

	// activate 10 other backend
	pickInfra := func(i int) string {
		if i&1 == 0 {
			return "Azure"
		}
		return "Alibaba"
	}
	for i := 0; i < 10; i++ {
		spawner.newMarbleAsync("backend_other", pickInfra(i), true)
	}

	// activate 10 frontend
	for i := 0; i < 10; i++ {
		spawner.newMarbleAsync("frontend", pickInfra(i), true)
	}

	spawner.wg.Wait()
}

type marbleSpawner struct {
	manifest   Manifest
	validator  *quote.MockValidator
	issuer     quote.Issuer
	coreServer *Core
	assert     *assert.Assertions
	wg         sync.WaitGroup
}

func (ms *marbleSpawner) newMarble(marbleType string, infraName string, shouldSucceed bool) {
	cert, csr, _ := util.MustGenerateTestMarbleCredentials()

	// create mock quote using values from the manifest
	quote, err := ms.issuer.Issue(cert.Raw)
	ms.assert.NotNil(quote)
	ms.assert.Nil(err)
	marble, ok := ms.manifest.Marbles[marbleType]
	ms.assert.True(ok)
	pkg, ok := ms.manifest.Packages[marble.Package]
	ms.assert.True(ok)
	infra, ok := ms.manifest.Infrastructures[infraName]
	ms.assert.True(ok)
	ms.validator.AddValidQuote(quote, cert.Raw, pkg, infra)

	tlsInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		},
	}

	ctx := peer.NewContext(context.TODO(), &peer.Peer{
		AuthInfo: tlsInfo,
	})

	resp, err := ms.coreServer.Activate(ctx, &rpc.ActivationReq{
		CSR:        csr,
		MarbleType: marbleType,
		Quote:      quote,
		UUID:       uuid.New().String(),
	})

	if !shouldSucceed {
		ms.assert.Error(err)
		ms.assert.Nil(resp)
		return
	}
	ms.assert.NoError(err, "Activate failed: %v", err)
	ms.assert.NotNil(resp)

	// Validate response
	params := resp.GetParameters()
	// Validate Files
	if marble.Parameters.Files != nil {
		ms.assert.Equal(marble.Parameters.Files, params.Files)
	}
	// Validate Argv
	if marble.Parameters.Argv != nil {
		ms.assert.Equal(marble.Parameters.Argv, params.Argv)
	}

	// Validate SealKey
	sealKey, err := hex.DecodeString(params.Env["SEAL_KEY"])
	ms.assert.NoError(err)
	ms.assert.Len(sealKey, 32)

	// Validate Marble Key
	p, _ := pem.Decode([]byte(params.Env["MARBLE_KEY"]))
	ms.assert.NotNil(p)

	// Validate Cert
	p, _ = pem.Decode([]byte(params.Env["MARBLE_CERT"]))
	ms.assert.NotNil(p)
	newCert, err := x509.ParseCertificate(p.Bytes)
	ms.assert.NoError(err)
	ms.assert.Equal(CoordinatorName, newCert.Issuer.CommonName)
	// Check CommonName
	_, err = uuid.Parse(newCert.Subject.CommonName)
	ms.assert.NoError(err, "cert.Subject.CommonName is not a valid UUID: %v", err)
	// Check KeyUusage:
	ms.assert.Equal(cert.KeyUsage, newCert.KeyUsage)
	// Check ExtKeyUsage
	ms.assert.Equal(cert.ExtKeyUsage, newCert.ExtKeyUsage)
	// Check DNSNames
	ms.assert.Equal(cert.DNSNames, newCert.DNSNames)
	ms.assert.Equal(cert.IPAddresses, newCert.IPAddresses)
	// Check Signature
	ms.assert.NoError(ms.coreServer.cert.CheckSignature(newCert.SignatureAlgorithm, newCert.RawTBSCertificate, newCert.Signature))

	// Validate generated secret (only specified in backend_first)
	if marbleType == "backend_first" {
		ms.assert.Len(params.Env["TEST_SECRET_RAW"], 16)
	} else {
		ms.assert.Empty(params.Env["TEST_SECRET_RAW"])
	}

	// Check cert-chain
	roots := x509.NewCertPool()
	ms.assert.True(roots.AppendCertsFromPEM([]byte(params.Env["ROOT_CA"])), "cannot parse rootCA")
	opts := x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "localhost",
		KeyUsages: newCert.ExtKeyUsage,
	}
	_, err = newCert.Verify(opts)
	ms.assert.NoError(err, "failed to verify new certificate: %v", err)

	if marbleType == "backend_first" {
		// Validate generated secret certificate
		p, _ = pem.Decode([]byte(params.Env["TEST_SECRET_CERT"]))
		ms.assert.NotNil(p)
		secretCert, err := x509.ParseCertificate(p.Bytes)
		ms.assert.NotNil(p)
		ms.assert.NoError(err)
		_, err = secretCert.Verify(opts)
		ms.assert.NoError(err, "failed to verify secret certificate with root CA: %v", err)
	}
}

func (ms *marbleSpawner) newMarbleAsync(marbleType string, infraName string, shouldSucceed bool) {
	ms.wg.Add(1)
	go func() {
		ms.newMarble(marbleType, infraName, shouldSucceed)
		ms.wg.Done()
	}()
}

func TestParseSecrets(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Generate keys
	key, err := rsa.GenerateKey(rand.Reader, int(2048))
	if err != nil {
		panic(err)
	}
	privKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	pubKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}

	// Create some demo certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(42),
		IsCA:         false,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
	}

	testCertRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	testCert, err := x509.ParseCertificate(testCertRaw)
	if err != nil {
		panic(err)
	}

	// Define secrets
	testSecrets := map[string]Secret{
		"mysecret":          {Type: "raw", Size: 16, Public: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, Private: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
		"anothercoolsecret": {Type: "raw", Size: 8, Public: []byte{7, 6, 5, 4, 3, 2, 1, 0}, Private: []byte{7, 6, 5, 4, 3, 2, 1, 0}},
		"testcertificate":   {Type: "cert-rsa", Size: 2048, Cert: *testCert, Public: pubKey, Private: privKey},
	}

	testReservedSecrets := reservedSecrets{
		RootCA:     Secret{Public: []byte{0, 0, 42}, Private: []byte{0, 0, 7}},
		MarbleCert: Secret{Public: []byte{42, 0, 0}, Private: []byte{7, 0, 0}},
		SealKey:    Secret{Public: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, Private: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
	}

	testWrappedSecrets := secretsWrapper{
		Marblerun: testReservedSecrets,
		Secrets:   testSecrets,
	}

	// Test all formats, pem should fail for raw/symmetric secrets
	parsedSecret, err := parseSecrets("{{ raw .Secrets.mysecret }}", testWrappedSecrets)
	require.NoError(err)
	assert.EqualValues(testSecrets["mysecret"].Public, []byte(parsedSecret))

	parsedSecret, err = parseSecrets("{{ hex .Secrets.mysecret }}", testWrappedSecrets)
	require.NoError(err)
	assert.EqualValues("000102030405060708090a0b0c0d0e0f", parsedSecret)

	_, err = parseSecrets("{{ pem .Secrets.mysecret }}", testWrappedSecrets)
	assert.Error(err)

	parsedSecret, err = parseSecrets("{{ base64 .Secrets.mysecret }}", testWrappedSecrets)
	require.NoError(err)
	assert.EqualValues("AAECAwQFBgcICQoLDA0ODw==", parsedSecret)

	// Check if we can decode a certificate from PEM
	parsedSecret, err = parseSecrets("{{ pem .Secrets.testcertificate.Cert }}", testWrappedSecrets)
	require.NoError(err)
	assert.Contains(parsedSecret, "-----BEGIN CERTIFICATE-----\n")

	p, _ := pem.Decode([]byte(parsedSecret))
	assert.NotNil(p)
	parsedCertificate, err := x509.ParseCertificate(p.Bytes)
	require.NoError(err)
	assert.EqualValues(testCert, parsedCertificate)

	// Test if we can access a second secret
	parsedSecret, err = parseSecrets("{{ raw .Secrets.anothercoolsecret }}", testWrappedSecrets)
	require.NoError(err)
	assert.EqualValues(testSecrets["anothercoolsecret"].Public, []byte(parsedSecret))

	// Test all the reserved placeholder secrets
	expectedResult := "-----BEGIN PUBLIC KEY-----\nAAAq\n-----END PUBLIC KEY-----\n"
	parsedSecret, err = parseSecrets("{{ pem .Marblerun.RootCA.Public }}", testWrappedSecrets)
	require.NoError(err)
	assert.EqualValues(expectedResult, parsedSecret)

	expectedResult = "-----BEGIN PUBLIC KEY-----\nKgAA\n-----END PUBLIC KEY-----\n"
	parsedSecret, err = parseSecrets("{{ pem .Marblerun.MarbleCert.Public }}", testWrappedSecrets)
	require.NoError(err)
	assert.EqualValues(expectedResult, parsedSecret)

	expectedResult = "-----BEGIN PRIVATE KEY-----\nBwAA\n-----END PRIVATE KEY-----\n"

	parsedSecret, err = parseSecrets("{{ pem .Marblerun.MarbleCert.Private }}", testWrappedSecrets)
	require.NoError(err)
	assert.EqualValues(expectedResult, parsedSecret)

	parsedSecret, err = parseSecrets("{{ hex .Marblerun.SealKey }}", testWrappedSecrets)
	require.NoError(err)
	assert.EqualValues("000102030405060708090a0b0c0d0e0f", parsedSecret)

	// We should get an error if we try to get a non-existing secret
	_, err = parseSecrets("{{ hex .Secrets.idontexist }}", testWrappedSecrets)
	assert.Error(err)
}
