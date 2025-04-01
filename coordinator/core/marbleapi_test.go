/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

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
	"strings"
	"sync"
	"testing"
	"time"

	libMarble "github.com/edgelesssys/ego/marble"
	"github.com/edgelesssys/marblerun/coordinator/clientapi"
	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper/testutil"
	globalconstants "github.com/edgelesssys/marblerun/internal/constants"
	"github.com/edgelesssys/marblerun/test"
	"github.com/edgelesssys/marblerun/util"
	"github.com/google/uuid"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestActivate(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// parse manifest
	var manifest manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.ManifestJSON), &manifest))

	zapLogger := zaptest.NewLogger(t)

	// create core
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	fs := afero.NewMemMapFs()
	recovery := recovery.NewSinglePartyRecovery()
	coreServer, err := NewCore([]string{"localhost"}, validator, issuer, stdstore.New(sealer, fs, "", zapLogger), recovery, zapLogger, nil, nil)
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
	spawner.newMarble(t, "backendFirst", "Azure", uuid.New(), false)

	// set manifest
	clientAPI, err := clientapi.New(coreServer.txHandle, coreServer.recovery, coreServer, zapLogger)
	require.NoError(err)
	_, err = clientAPI.SetManifest(context.Background(), []byte(test.ManifestJSON))
	require.NoError(err)

	// activate first backend
	spawner.newMarble(t, "backendFirst", "Azure", uuid.New(), true)

	// try to activate another first backend
	spawner.newMarble(t, "backendFirst", "Azure", uuid.New(), false)

	// activate 10 other backend
	pickInfra := func(i int) string {
		if i&1 == 0 {
			return "Azure"
		}
		return "Alibaba"
	}
	for i := 0; i < 10; i++ {
		spawner.newMarbleAsync(t, "backendOther", pickInfra(i), true)
	}

	// activate 10 frontend
	for i := 0; i < 10; i++ {
		spawner.newMarbleAsync(t, "frontend", pickInfra(i), true)
	}

	spawner.wg.Wait()

	// Check if non-shared secret with the same name is indeed not the same in different marbles
	assert.EqualValues(spawner.backendFirstSharedCert, spawner.backendOtherSharedCert, "Shared secrets were different across different marbles, but were supposed to be the same.")
	assert.NotEqualValues(spawner.backendFirstUniqueCert, spawner.backendOtherUniqueCert, "Non-shared secrets were the same across different marbles, but were supposed to be unique.")
}

func TestMarbleSecretDerivation(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	fileMap := map[string]manifest.File{
		"secret": {
			Data:     "{{ hex .Secrets.symmetricKeyPrivate }}",
			Encoding: "string",
		},
	}

	// parse manifest
	var manifest manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.ManifestJSON), &manifest))

	// Disable secret binding for backend Marbles
	// This should cause the Coordinator to generate the same secrets as long as they provide the same UUID
	backendMarble := manifest.Marbles["backendFirst"]
	backendMarble.DisableSecretBinding = true
	backendMarble.MaxActivations = 0
	backendMarble.Parameters.Files = fileMap
	manifest.Marbles["backendFirst"] = backendMarble

	backendOther := manifest.Marbles["backendOther"]
	backendOther.DisableSecretBinding = true
	backendOther.Parameters.Files = fileMap
	manifest.Marbles["backendOther"] = backendOther

	frontendMarble := manifest.Marbles["frontend"]
	frontendMarble.Parameters.Files = fileMap
	manifest.Marbles["frontend"] = frontendMarble

	mnf, err := json.Marshal(manifest)
	require.NoError(err)

	zapLogger := zaptest.NewLogger(t)

	// create core
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	fs := afero.NewMemMapFs()
	recovery := recovery.NewSinglePartyRecovery()
	coreServer, err := NewCore([]string{"localhost"}, validator, issuer, stdstore.New(sealer, fs, "", zapLogger), recovery, zapLogger, nil, nil)
	require.NoError(err)
	require.NotNil(coreServer)

	// set manifest
	clientAPI, err := clientapi.New(coreServer.txHandle, coreServer.recovery, coreServer, zapLogger)
	require.NoError(err)
	_, err = clientAPI.SetManifest(context.Background(), mnf)
	require.NoError(err)

	activate := func(uuid uuid.UUID, marbleType string) []byte {
		cert, csr, _ := util.MustGenerateTestMarbleCredentials()

		// create mock quote using values from the manifest
		quote, err := issuer.Issue(cert.Raw)
		assert.NotNil(quote)
		assert.Nil(err)
		marble, ok := manifest.Marbles[marbleType]
		assert.True(ok)
		pkg, ok := manifest.Packages[marble.Package]
		assert.True(ok)
		infra, ok := manifest.Infrastructures["Azure"]
		assert.True(ok)
		validator.AddValidQuote(quote, cert.Raw, pkg, infra)

		tlsInfo := credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		}

		ctx := peer.NewContext(context.Background(), &peer.Peer{
			AuthInfo: tlsInfo,
		})

		resp, err := coreServer.Activate(ctx, &rpc.ActivationReq{
			CSR:        csr,
			MarbleType: marbleType,
			Quote:      quote,
			UUID:       uuid.String(),
		})
		require.NoError(err)
		secret, ok := resp.Parameters.Files["secret"]
		require.True(ok)
		return secret
	}

	// Activate marbles with different UUIDs
	// They should all receive different secrets
	backendFirstSecret := activate(uuid.New(), "backendFirst")
	backendOtherSecret := activate(uuid.New(), "backendOther")
	frontendSecret := activate(uuid.New(), "frontend")

	assert.NotEqual(backendFirstSecret, backendOtherSecret)
	assert.NotEqual(backendFirstSecret, frontendSecret)
	assert.NotEqual(backendOtherSecret, frontendSecret)

	// Activate marbles with the same UUID
	// The backend marbles should receive the same secret,
	// while the frontend marble should receive a different one
	uuid1 := uuid.New()
	backendFirstSecret = activate(uuid1, "backendFirst")
	backendOtherSecret = activate(uuid1, "backendOther")
	frontendSecret = activate(uuid1, "frontend")

	assert.Equal(backendFirstSecret, backendOtherSecret)
	assert.NotEqual(backendFirstSecret, frontendSecret)

	// Activate the same marble with different UUIDs
	// The secrets should be different
	uuid2 := uuid.New()
	backendFirstSecret2 := activate(uuid2, "backendFirst")
	frontendSecret2 := activate(uuid2, "frontend")

	assert.NotEqual(backendFirstSecret, backendFirstSecret2)
	assert.NotEqual(frontendSecret, frontendSecret2)
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

func (ms *marbleSpawner) newMarble(t *testing.T, marbleType string, infraName string, marbleUUID uuid.UUID, shouldSucceed bool) {
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

	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: tlsInfo,
	})

	resp, err := ms.coreServer.Activate(ctx, &rpc.ActivationReq{
		CSR:        csr,
		MarbleType: marbleType,
		Quote:      quote,
		UUID:       marbleUUID.String(),
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
	pIntermediate, rest := pem.Decode(rest)
	ms.assert.NotNil(pIntermediate)
	ms.assert.Empty(rest)

	newIntermediateCert, err := x509.ParseCertificate(pIntermediate.Bytes)
	ms.assert.NoError(err)
	newLeafCert, err := x509.ParseCertificate(pLeaf.Bytes)
	ms.assert.NoError(err)

	ms.assert.Equal(constants.CoordinatorName, newIntermediateCert.Issuer.CommonName)
	ms.assert.Equal(constants.CoordinatorIntermediateName, newLeafCert.Issuer.CommonName)

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

	rootCert := testutil.GetCertificate(t, ms.coreServer.txHandle, constants.SKCoordinatorRootCert)
	intermediateCert := testutil.GetCertificate(t, ms.coreServer.txHandle, constants.SKCoordinatorIntermediateCert)
	marbleRootCert := testutil.GetCertificate(t, ms.coreServer.txHandle, constants.SKMarbleRootCert)
	// Check Signature for both, intermediate certificate and leaf certificate
	ms.assert.NoError(rootCert.CheckSignature(intermediateCert.SignatureAlgorithm, intermediateCert.RawTBSCertificate, intermediateCert.Signature))
	ms.assert.NoError(newIntermediateCert.CheckSignature(newLeafCert.SignatureAlgorithm, newLeafCert.RawTBSCertificate, newLeafCert.Signature))
	ms.assert.NoError(marbleRootCert.CheckSignature(newLeafCert.SignatureAlgorithm, newLeafCert.RawTBSCertificate, newLeafCert.Signature))

	// Validate generated secret (only specified in backendFirst)
	if marbleType == "backendFirst" {
		ms.assert.Len(params.Env["TEST_SECRET_SYMMETRIC_KEY"], 32)
	} else {
		ms.assert.Empty(params.Env["TEST_SECRET_SYMMETRIC_KEY"])
	}

	// Check cert-chain
	roots := x509.NewCertPool()
	ms.assert.True(roots.AppendCertsFromPEM(params.Env[libMarble.MarbleEnvironmentRootCA]), "cannot parse rootCA")
	opts := x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "localhost",
		KeyUsages: newLeafCert.ExtKeyUsage,
	}
	_, err = newLeafCert.Verify(opts)
	ms.assert.NoError(err, "failed to verify new certificate: %v", err)

	// Shared & non-shared secret checks
	switch marbleType {
	case "backendFirst":
		// Validate generated shared secret certificate
		// backendFirst only runs once, so need for a mutex & checks
		ms.backendFirstSharedCert = ms.verifyCertificateFromEnvironment("TEST_SECRET_CERT", params, opts)
		ms.backendFirstUniqueCert = ms.verifyCertificateFromEnvironment("TEST_SECRET_PRIVATE_CERT", params, opts)
	case "backendOther":
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
	configBytes := params.Env[globalconstants.EnvMarbleTTLSConfig]
	switch marbleType {
	case "backendFirst":
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
	case "backendOther":
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
	default:
		ms.assert.Empty(configBytes)
	}
}

func (ms *marbleSpawner) newMarbleAsync(t *testing.T, marbleType string, infraName string, shouldSucceed bool) {
	ms.wg.Add(1)
	go func() {
		ms.newMarble(t, marbleType, infraName, uuid.New(), shouldSucceed)
		ms.wg.Done()
	}()
}

func (ms *marbleSpawner) verifyCertificateFromEnvironment(envName string, params *rpc.Parameters, opts x509.VerifyOptions) x509.Certificate {
	p, _ := pem.Decode(params.Env[envName])
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
		"mysecret":          {Type: manifest.SecretTypeSymmetricKey, Size: 16, Public: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, Private: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
		"anothercoolsecret": {Type: manifest.SecretTypeSymmetricKey, Size: 8, Public: []byte{7, 6, 5, 4, 3, 2, 1, 0}, Private: []byte{7, 6, 5, 4, 3, 2, 1, 0}},
		"testcertificate":   {Type: manifest.SecretTypeCertRSA, Size: 2048, Cert: manifest.Certificate(*testCert), Public: pubKey, Private: privKey},
		"emptysecret":       {},
	}

	testReservedSecrets := manifest.ReservedSecrets{
		RootCA:     manifest.Secret{Public: []byte{0, 0, 42}, Private: []byte{0, 0, 7}},
		MarbleCert: manifest.Secret{Public: []byte{42, 0, 0}, Private: []byte{7, 0, 0}},
	}

	testWrappedSecrets := manifest.SecretsWrapper{
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
		"plainSecret": {Type: manifest.SecretTypePlain, Public: []byte{1, 2, 3}},
		"nullSecret":  {Type: manifest.SecretTypePlain, Public: []byte{0, 1, 2}},
		"otherSecret": {Type: manifest.SecretTypeSymmetricKey, Public: []byte{4, 5, 6}},
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
	ctx := context.Background()

	// parse manifest
	var manifest manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.ManifestJSONWithRecoveryKey), &manifest))

	zapLogger := zaptest.NewLogger(t)

	// create core
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	fs := afero.NewMemMapFs()
	recovery := recovery.NewSinglePartyRecovery()
	coreServer, err := NewCore([]string{"localhost"}, validator, issuer, stdstore.New(sealer, fs, "", zapLogger), recovery, zapLogger, nil, nil)
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
	clientAPI, err := clientapi.New(coreServer.txHandle, coreServer.recovery, coreServer, zapLogger)
	require.NoError(err)
	_, err = clientAPI.SetManifest(ctx, []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)

	admin := testutil.GetUser(t, coreServer.txHandle, "admin")

	// try to activate another first backend, should succeed as SecurityLevel matches the definition in the manifest
	spawner.newMarble(t, "frontend", "Azure", uuid.New(), true)

	// update manifest
	err = clientAPI.UpdateManifest(ctx, []byte(test.UpdateManifest), admin)
	require.NoError(err)

	// try to activate another first backend, should fail as required SecurityLevel is now higher after manifest update
	spawner.newMarble(t, "frontend", "Azure", uuid.New(), false)

	// Use a new core and test if updated manifest persisted after restart
	coreServer2, err := NewCore([]string{"localhost"}, validator, issuer, stdstore.New(sealer, fs, "", zapLogger), recovery, zapLogger, nil, nil)
	require.NoError(err)
	coreServer2State := testutil.GetState(t, coreServer2.txHandle)
	coreServer2UpdatedPkg := testutil.GetPackage(t, coreServer2.txHandle, "frontend")
	assert.Equal(state.AcceptingMarbles, coreServer2State)
	assert.EqualValues(5, *coreServer2UpdatedPkg.SecurityVersion)

	// This should still fail after a restart, as the update manifest should have been reloaded from the sealed state correctly
	spawner.coreServer = coreServer2
	spawner.newMarble(t, "frontend", "Azure", uuid.New(), false)
}

func (ms *marbleSpawner) shortMarbleActivation(t *testing.T, marbleType string, infraName string) {
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

	ctx := peer.NewContext(context.Background(), &peer.Peer{
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
	coreServerManifest := testutil.GetManifest(t, ms.coreServer.txHandle)
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

	zapLogger := zaptest.NewLogger(t)

	// create core
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	fs := afero.NewMemMapFs()
	recovery := recovery.NewSinglePartyRecovery()
	coreServer, err := NewCore([]string{"localhost"}, validator, issuer, stdstore.New(sealer, fs, "", zapLogger), recovery, zapLogger, nil, nil)
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
	clientAPI, err := clientapi.New(coreServer.txHandle, coreServer.recovery, coreServer, zapLogger)
	require.NoError(err)
	_, err = clientAPI.SetManifest(context.Background(), []byte(test.ManifestJSONMissingParameters))
	require.NoError(err)

	spawner.shortMarbleActivation(t, "frontend", "Azure")
}

func TestActivateWithTTLSforMarbleWithoutEnvVars(t *testing.T) {
	// Regression: TTLS config wasn't correctly set for marbles without env vars

	assert := assert.New(t)
	require := require.New(t)

	log := zaptest.NewLogger(t)
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	store := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "", log)
	coreServer, err := NewCore(nil, validator, issuer, store, recovery.NewSinglePartyRecovery(), log, nil, nil)
	require.NoError(err)

	clientAPI, err := clientapi.New(coreServer.txHandle, coreServer.recovery, coreServer, coreServer.log)
	require.NoError(err)

	_, err = clientAPI.SetManifest(context.Background(), []byte(`
{
    "Packages": {
        "pkg": {
            "UniqueID": "0"
        }
    },
    "Marbles": {
        "marble": {
            "Package": "pkg",
            "TLS": [
                "tls"
            ]
        }
    },
    "TLS": {
        "tls": {
            "Incoming": [
                {
                    "Port": "2000"
                }
            ]
        }
    }
}
	`))
	require.NoError(err)

	cert, csr, _ := util.MustGenerateTestMarbleCredentials()
	qu, err := issuer.Issue(cert.Raw)
	require.NoError(err)
	validator.AddValidQuote(qu, cert.Raw, quote.PackageProperties{UniqueID: "0"}, quote.InfrastructureProperties{})

	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		},
	})

	resp, err := coreServer.Activate(ctx, &rpc.ActivationReq{Quote: qu, CSR: csr, MarbleType: "marble", UUID: uuid.NewString()})
	require.NoError(err)
	assert.True(strings.HasPrefix(string(resp.Parameters.Env[globalconstants.EnvMarbleTTLSConfig]), `{"tls":{"Incoming":{"*:2000":{"cacrt":"-----BEGIN CERTIFICATE-----`))
}
