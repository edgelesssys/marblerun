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
	"encoding/json"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	libMarble "github.com/edgelesssys/ego/marble"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"github.com/edgelesssys/marblerun/coordinator/seal"
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
	var manifest manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.ManifestJSON), &manifest))

	// setup mock zaplogger which can be passed to Core
	zapLogger, err := zap.NewDevelopment()
	require.NoError(err)
	defer zapLogger.Sync()

	// create core
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	recovery := recovery.NewSinglePartyRecovery()
	coreServer, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger, nil, nil)
	require.NoError(err)
	require.NotNil(coreServer)

	spawner := marbleSpawner{
		assert:     assert,
		require:    require,
		issuer:     issuer,
		validator:  validator,
		manifest:   manifest,
		coreServer: coreServer,
	}

	// try to activate first backend marble prematurely before manifest is set
	spawner.newMarble("backendFirst", "Azure", false)

	// set manifest
	_, err = coreServer.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	require.NoError(err)

	// activate first backend
	spawner.newMarble("backendFirst", "Azure", true)

	// try to activate another first backend
	spawner.newMarble("backendFirst", "Azure", false)

	// activate 10 other backend
	pickInfra := func(i int) string {
		if i&1 == 0 {
			return "Azure"
		}
		return "Alibaba"
	}
	for i := 0; i < 10; i++ {
		spawner.newMarbleAsync("backendOther", pickInfra(i), true)
	}

	// activate 10 frontend
	for i := 0; i < 10; i++ {
		spawner.newMarbleAsync("frontend", pickInfra(i), true)
	}

	spawner.wg.Wait()

	// Check if non-shared secret with the same name is indeed not the same in different marbles
	assert.EqualValues(spawner.backendFirstSharedCert, spawner.backendOtherSharedCert, "Shared secrets were different across different marbles, but were supposed to be the same.")
	assert.NotEqualValues(spawner.backendFirstUniqueCert, spawner.backendOtherUniqueCert, "Non-shared secrets were the same across different marbles, but were supposed to be unique.")
}

type marbleSpawner struct {
	manifest               manifest.Manifest
	validator              *quote.MockValidator
	issuer                 quote.Issuer
	coreServer             *Core
	assert                 *assert.Assertions
	require                *require.Assertions
	wg                     sync.WaitGroup
	mutex                  sync.Mutex
	backendFirstSharedCert x509.Certificate
	backendFirstUniqueCert x509.Certificate
	backendOtherSharedCert x509.Certificate
	backendOtherUniqueCert x509.Certificate
}

func (ms *marbleSpawner) newMarble(marbleType string, infraName string, shouldSucceed bool) string {
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

	uuidStr := uuid.New().String()
	resp, err := ms.coreServer.Activate(ctx, &rpc.ActivationReq{
		CSR:        csr,
		MarbleType: marbleType,
		Quote:      quote,
		UUID:       uuidStr,
	})

	if !shouldSucceed {
		ms.assert.Error(err)
		ms.assert.Nil(resp)
		return uuidStr
	}
	ms.assert.NoError(err, "Activate failed: %v", err)
	ms.assert.NotNil(resp)

	// Validate response
	params := resp.GetParameters()
	// Validate Files
	for k, v := range marble.Parameters.Files {
		ms.assert.EqualValues(v.Data, resp.Parameters.Files[k])
	}
	// Validate Argv
	ms.assert.Equal(marble.Parameters.Argv, params.Argv)

	// Validate Marble Key
	pMarbleKey, _ := pem.Decode(params.Env[libMarble.MarbleEnvironmentPrivateKey])
	ms.assert.NotNil(pMarbleKey)

	// Validate Certificate Chain
	pLeaf, rest := pem.Decode(params.Env[libMarble.MarbleEnvironmentCertificateChain])
	ms.assert.NotNil(pLeaf)
	ms.assert.NotEmpty(rest)
	pMarbleRoot, rest := pem.Decode(rest)
	ms.assert.NotNil(pMarbleRoot)
	ms.assert.Empty(rest)

	newMarbleRootCert, err := x509.ParseCertificate(pMarbleRoot.Bytes)
	ms.assert.NoError(err)
	newLeafCert, err := x509.ParseCertificate(pLeaf.Bytes)
	ms.assert.NoError(err)

	ms.assert.Equal(coordinatorIntermediateName, newMarbleRootCert.Issuer.CommonName)
	ms.assert.Equal(coordinatorIntermediateName, newLeafCert.Issuer.CommonName)

	// Check CommonName for leaf certificate
	_, err = uuid.Parse(newLeafCert.Subject.CommonName)
	ms.assert.NoError(err, "cert.Subject.CommonName is not a valid UUID: %v", err)
	// Check KeyUsage for leaf certificate
	ms.assert.Equal(cert.KeyUsage, newLeafCert.KeyUsage)
	// Check ExtKeyUsage for leaf certificate
	ms.assert.Equal(cert.ExtKeyUsage, newLeafCert.ExtKeyUsage)
	// Check DNSNames for leaf certificate
	ms.assert.Equal(cert.DNSNames, newLeafCert.DNSNames)
	ms.assert.Equal(cert.IPAddresses, newLeafCert.IPAddresses)

	rootCert, err := ms.coreServer.data.getCertificate(sKCoordinatorRootCert)
	ms.assert.NoError(err)
	intermediateCert, err := ms.coreServer.data.getCertificate(skCoordinatorIntermediateCert)
	ms.assert.NoError(err)
	marbleRootCert, err := ms.coreServer.data.getCertificate(sKMarbleRootCert)
	ms.assert.NoError(err)
	// Check Signature for both, intermediate certificate and leaf certificate
	ms.assert.NoError(rootCert.CheckSignature(intermediateCert.SignatureAlgorithm, intermediateCert.RawTBSCertificate, intermediateCert.Signature))
	ms.assert.NoError(newMarbleRootCert.CheckSignature(newMarbleRootCert.SignatureAlgorithm, newMarbleRootCert.RawTBSCertificate, newMarbleRootCert.Signature))
	ms.assert.NoError(marbleRootCert.CheckSignature(newLeafCert.SignatureAlgorithm, newLeafCert.RawTBSCertificate, newLeafCert.Signature))

	// Validate generated secret (only specified in backendFirst)
	if marbleType == "backendFirst" {
		ms.assert.Len(params.Env["TEST_SECRET_SYMMETRIC_KEY"], 32)
	} else {
		ms.assert.Empty(params.Env["TEST_SECRET_SYMMETRIC_KEY"])
	}

	// Check cert-chain
	roots := x509.NewCertPool()
	ms.assert.True(roots.AppendCertsFromPEM([]byte(params.Env[libMarble.MarbleEnvironmentRootCA])), "cannot parse rootCA")
	opts := x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "localhost",
		KeyUsages: newLeafCert.ExtKeyUsage,
	}
	_, err = newLeafCert.Verify(opts)
	ms.assert.NoError(err, "failed to verify new certificate: %v", err)

	// Shared & non-shared secret checks
	if marbleType == "backendFirst" {
		// Validate generated shared secret certificate
		// backendFirst only runs once, so need for a mutex & checks
		ms.backendFirstSharedCert = ms.verifyCertificateFromEnvironment("TEST_SECRET_CERT", params, opts)
		ms.backendFirstUniqueCert = ms.verifyCertificateFromEnvironment("TEST_SECRET_PRIVATE_CERT", params, opts)
	} else if marbleType == "backendOther" {
		// Validate generated shared secret certificate
		// Since we're running async and multiple times, let's avoid a race condition here and only get the certificate from one instance
		ms.mutex.Lock()
		if ms.backendOtherSharedCert.Raw == nil {
			ms.backendOtherSharedCert = ms.verifyCertificateFromEnvironment("TEST_SECRET_CERT", params, opts)
		}
		if ms.backendOtherUniqueCert.Raw == nil {
			ms.backendOtherUniqueCert = ms.verifyCertificateFromEnvironment("TEST_SECRET_PRIVATE_CERT", params, opts)
		}
		ms.mutex.Unlock()
	}

	// Validate ttls conf
	config := make(map[string]map[string]map[string]map[string]interface{})
	configBytes := []byte(params.Env["MARBLE_TTLS_CONFIG"])
	if marbleType == "backendFirst" {
		ms.assert.NoError(json.Unmarshal(configBytes, &config))

		ms.assert.NotEqual(nil, config["tls"]["Outgoing"]["localhost:8080"]["cacrt"])
		ms.assert.NotEqual(nil, config["tls"]["Outgoing"]["localhost:8080"]["clicrt"])
		ms.assert.NotEqual(nil, config["tls"]["Outgoing"]["localhost:8080"]["clikey"])

		ms.assert.NotEqual(nil, config["tls"]["Outgoing"]["service.namespace:4242"]["cacrt"])
		ms.assert.NotEqual(nil, config["tls"]["Outgoing"]["service.namespace:4242"]["clicrt"])
		ms.assert.NotEqual(nil, config["tls"]["Outgoing"]["service.namespace:4242"]["clikey"])

		ms.assert.NotEqual(nil, config["tls"]["Incoming"]["*:8080"]["cacrt"])
		ms.assert.NotEmpty(config["tls"]["Incoming"]["*:8080"]["clicrt"])
		ms.assert.NotEmpty(config["tls"]["Incoming"]["*:8080"]["clikey"])
		ms.assert.True(config["tls"]["Incoming"]["*:8080"]["clientAuth"].(bool))
	} else if marbleType == "backendOther" {
		ms.assert.NoError(json.Unmarshal(configBytes, &config))
		ms.assert.NotEqual(nil, config["tls"]["Outgoing"]["localhost:8080"]["cacrt"])
		ms.assert.NotEqual(nil, config["tls"]["Outgoing"]["localhost:8080"]["clicrt"])
		ms.assert.NotEqual(nil, config["tls"]["Outgoing"]["localhost:8080"]["clikey"])

		ms.assert.NotEqual(nil, config["tls"]["Outgoing"]["service.namespace:4242"]["cacrt"])
		ms.assert.NotEqual(nil, config["tls"]["Outgoing"]["service.namespace:4242"]["clicrt"])
		ms.assert.NotEqual(nil, config["tls"]["Outgoing"]["service.namespace:4242"]["clikey"])

		ms.assert.NotEqual(nil, config["tls"]["Outgoing"]["example.com:40000"]["cacrt"])
		ms.assert.NotEqual(nil, config["tls"]["Outgoing"]["example.com:40000"]["clicrt"])
		ms.assert.NotEqual(nil, config["tls"]["Outgoing"]["example.com:40000"]["clikey"])

		ms.assert.NotEqual(nil, config["tls"]["Incoming"]["*:8080"]["cacrt"])
		ms.assert.NotEmpty(config["tls"]["Incoming"]["*:8080"]["clicrt"])
		ms.assert.NotEmpty(config["tls"]["Incoming"]["*:8080"]["clikey"])
		ms.assert.False(config["tls"]["Incoming"]["*:8080"]["clientAuth"].(bool))
	} else {
		ms.assert.Empty(configBytes)
	}
	return uuidStr
}

func (ms *marbleSpawner) newMarbleAsync(marbleType string, infraName string, shouldSucceed bool) {
	ms.wg.Add(1)
	go func() {
		ms.newMarble(marbleType, infraName, shouldSucceed)
		ms.wg.Done()
	}()
}

func (ms *marbleSpawner) verifyCertificateFromEnvironment(envName string, params *rpc.Parameters, opts x509.VerifyOptions) x509.Certificate {
	p, _ := pem.Decode([]byte(params.Env[envName]))
	ms.require.NotNil(p)
	certificate, err := x509.ParseCertificate(p.Bytes)
	ms.require.NoError(err)

	// Verify if our certificate was signed correctly by the Coordinator's root CA
	_, err = certificate.Verify(opts)
	ms.assert.NoError(err, "failed to verify secret certificate with root CA: %v", err)

	// Check if our certificate does actually expire 7 days, as specified, after it was generated
	ms.assert.InDelta(7*24, certificate.NotAfter.Sub(certificate.NotBefore).Hours(), 2)

	return *certificate
}

func TestParseSecrets(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Generate keys
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(err)
	privKey, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(err)
	pubKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(err)

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
	testSecrets := map[string]manifest.Secret{
		"mysecret":          {Type: "symmetric-key", Size: 16, Public: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, Private: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
		"anothercoolsecret": {Type: "symmetric-key", Size: 8, Public: []byte{7, 6, 5, 4, 3, 2, 1, 0}, Private: []byte{7, 6, 5, 4, 3, 2, 1, 0}},
		"testcertificate":   {Type: "cert-rsa", Size: 2048, Cert: manifest.Certificate(*testCert), Public: pubKey, Private: privKey},
		"emptysecret":       {},
	}

	testReservedSecrets := reservedSecrets{
		RootCA:     manifest.Secret{Public: []byte{0, 0, 42}, Private: []byte{0, 0, 7}},
		MarbleCert: manifest.Secret{Public: []byte{42, 0, 0}, Private: []byte{7, 0, 0}},
	}

	testWrappedSecrets := secretsWrapper{
		MarbleRun: testReservedSecrets,
		Secrets:   testSecrets,
	}

	// Test all formats, pem should fail for raw/symmetric secrets
	parsedSecret, err := parseSecrets("{{ raw .Secrets.mysecret }}", manifest.ManifestFileTemplateFuncMap, testWrappedSecrets)
	require.NoError(err)
	assert.EqualValues(testSecrets["mysecret"].Public, []byte(parsedSecret))

	parsedSecret, err = parseSecrets("{{ hex .Secrets.mysecret }}", manifest.ManifestFileTemplateFuncMap, testWrappedSecrets)
	require.NoError(err)
	assert.EqualValues("000102030405060708090a0b0c0d0e0f", parsedSecret)

	_, err = parseSecrets("{{ pem .Secrets.mysecret }}", manifest.ManifestFileTemplateFuncMap, testWrappedSecrets)
	assert.Error(err)

	parsedSecret, err = parseSecrets("{{ base64 .Secrets.mysecret }}", manifest.ManifestFileTemplateFuncMap, testWrappedSecrets)
	require.NoError(err)
	assert.EqualValues("AAECAwQFBgcICQoLDA0ODw==", parsedSecret)

	// Check if we can decode a certificate from PEM
	parsedSecret, err = parseSecrets("{{ pem .Secrets.testcertificate.Cert }}", manifest.ManifestFileTemplateFuncMap, testWrappedSecrets)
	require.NoError(err)
	assert.Contains(parsedSecret, "-----BEGIN CERTIFICATE-----\n")

	p, _ := pem.Decode([]byte(parsedSecret))
	require.NotNil(p)
	parsedCertificate, err := x509.ParseCertificate(p.Bytes)
	require.NoError(err)
	assert.EqualValues(testCert, parsedCertificate)

	// Check if we can parse a certificate from the outputted raw type
	parsedSecret, err = parseSecrets("{{ raw .Secrets.testcertificate.Cert }}", manifest.ManifestFileTemplateFuncMap, testWrappedSecrets)
	require.NoError(err)
	parsedCertificate, err = x509.ParseCertificate([]byte(parsedSecret))
	require.NoError(err)
	assert.EqualValues(testCert, parsedCertificate)

	// Test if we can access a second secret
	parsedSecret, err = parseSecrets("{{ raw .Secrets.anothercoolsecret }}", manifest.ManifestFileTemplateFuncMap, testWrappedSecrets)
	require.NoError(err)
	assert.EqualValues(testSecrets["anothercoolsecret"].Public, []byte(parsedSecret))

	// Test all the reserved placeholder secrets
	expectedResult := "-----BEGIN PUBLIC KEY-----\nAAAq\n-----END PUBLIC KEY-----\n"
	parsedSecret, err = parseSecrets("{{ pem .MarbleRun.RootCA.Public }}", manifest.ManifestFileTemplateFuncMap, testWrappedSecrets)
	require.NoError(err)
	assert.EqualValues(expectedResult, parsedSecret)

	expectedResult = "-----BEGIN PUBLIC KEY-----\nKgAA\n-----END PUBLIC KEY-----\n"
	parsedSecret, err = parseSecrets("{{ pem .MarbleRun.MarbleCert.Public }}", manifest.ManifestFileTemplateFuncMap, testWrappedSecrets)
	require.NoError(err)
	assert.EqualValues(expectedResult, parsedSecret)

	expectedResult = "-----BEGIN PRIVATE KEY-----\nBwAA\n-----END PRIVATE KEY-----\n"

	parsedSecret, err = parseSecrets("{{ pem .MarbleRun.MarbleCert.Private }}", manifest.ManifestFileTemplateFuncMap, testWrappedSecrets)
	require.NoError(err)
	assert.EqualValues(expectedResult, parsedSecret)

	// We should get an error if we try to get a non-existing secret
	_, err = parseSecrets("{{ hex .Secrets.idontexist }}", manifest.ManifestFileTemplateFuncMap, testWrappedSecrets)
	assert.Error(err)

	// We should get an error if we try to access an empty secret
	_, err = parseSecrets("{{ hex .Secrets.emptysecret }}", manifest.ManifestFileTemplateFuncMap, testWrappedSecrets)
	assert.Error(err)

	testWrappedSecrets.Secrets = map[string]manifest.Secret{
		"plainSecret": {Type: "plain", Public: []byte{1, 2, 3}},
		"nullSecret":  {Type: "plain", Public: []byte{0, 1, 2}},
		"otherSecret": {Type: "symmetric-key", Public: []byte{4, 5, 6}},
	}

	// plain secrets are allowed to use string formating
	_, err = parseSecrets("{{ string .Secrets.plainSecret }}", manifest.ManifestEnvTemplateFuncMap, testWrappedSecrets)
	assert.NoError(err)

	// NULL bytes in secret results in an error
	_, err = parseSecrets("{{ string .Secrets.nullSecret }}", manifest.ManifestEnvTemplateFuncMap, testWrappedSecrets)
	assert.Error(err)

	// non plain secrets always result in an error
	_, err = parseSecrets("{{ string .Secrets.otherSecret }}", manifest.ManifestEnvTemplateFuncMap, testWrappedSecrets)
	assert.Error(err)
}

func TestSecurityLevelUpdate(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// parse manifest
	var manifest manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.ManifestJSONWithRecoveryKey), &manifest))

	// setup mock zaplogger which can be passed to Core
	zapLogger, err := zap.NewDevelopment()
	require.NoError(err)
	defer zapLogger.Sync()

	// create core
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	recovery := recovery.NewSinglePartyRecovery()
	coreServer, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger, nil, nil)
	require.NoError(err)
	require.NotNil(coreServer)

	spawner := marbleSpawner{
		assert:     assert,
		require:    require,
		issuer:     issuer,
		validator:  validator,
		manifest:   manifest,
		coreServer: coreServer,
	}
	// set manifest
	_, err = coreServer.SetManifest(context.TODO(), []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)

	admin, err := coreServer.data.getUser("admin")
	assert.NoError(err)

	// try to activate another first backend, should succeed as SecurityLevel matches the definition in the manifest
	spawner.newMarble("frontend", "Azure", true)

	// update manifest
	err = coreServer.UpdateManifest(context.TODO(), []byte(test.UpdateManifest), admin)
	require.NoError(err)

	// try to activate another first backend, should fail as required SecurityLevel is now higher after manifest update
	spawner.newMarble("frontend", "Azure", false)

	// Use a new core and test if updated manifest persisted after restart
	coreServer2, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger, nil, nil)
	require.NoError(err)
	coreServer2State, err := coreServer2.data.getState()
	assert.NoError(err)
	coreServer2UpdatedPkg, err := coreServer2.data.getPackage("frontend")
	assert.NoError(err)
	assert.Equal(stateAcceptingMarbles, coreServer2State)
	assert.EqualValues(5, *coreServer2UpdatedPkg.SecurityVersion)

	// This should still fail after a restart, as the update manifest should have been reloaded from the sealed state correctly
	spawner.coreServer = coreServer2
	spawner.newMarble("frontend", "Azure", false)
}

func (ms *marbleSpawner) shortMarbleActivation(marbleType string, infraName string, shouldSucceed bool) {
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

	ms.assert.NoError(err, "Activate failed: %v", err)
	ms.assert.NotNil(resp)

	// Validate response
	params := resp.GetParameters()
	// Get the marble from the manifest set on the coreServer since this one sets default values for empty values
	coreServerManifest, err := ms.coreServer.data.getManifest()
	ms.assert.NoError(err)
	marble = coreServerManifest.Marbles[marbleType]
	// Validate Files
	for k, v := range marble.Parameters.Files {
		ms.assert.EqualValues(v, params.Files[k])
	}
	// Validate Argv
	ms.assert.EqualValues(marble.Parameters.Argv, params.Argv)
}

func TestActivateWithMissingParameters(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// parse manifest
	var manifest manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.ManifestJSONMissingParameters), &manifest))

	// setup mock zaplogger which can be passed to Core
	zapLogger, err := zap.NewDevelopment()
	require.NoError(err)
	defer zapLogger.Sync()

	// create core
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	recovery := recovery.NewSinglePartyRecovery()
	coreServer, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger, nil, nil)
	require.NoError(err)
	require.NotNil(coreServer)

	spawner := marbleSpawner{
		assert:     assert,
		require:    require,
		issuer:     issuer,
		validator:  validator,
		manifest:   manifest,
		coreServer: coreServer,
	}
	// set manifest
	_, err = coreServer.SetManifest(context.TODO(), []byte(test.ManifestJSONMissingParameters))
	require.NoError(err)

	spawner.shortMarbleActivation("frontend", "Azure", true)
}
