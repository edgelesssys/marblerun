/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/edgelesssys/marblerun/coordinator/clientapi"
	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/distributor"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper/testutil"
	"github.com/edgelesssys/marblerun/test"
	"github.com/edgelesssys/marblerun/util"
	"github.com/google/uuid"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestCore(t *testing.T) {
	assert := assert.New(t)

	c := newCoreWithMocks()
	curState := testutil.GetState(t, c.txHandle)
	assert.Equal(state.AcceptingManifest, curState)
	rootCert := testutil.GetCertificate(t, c.txHandle, constants.SKCoordinatorRootCert)
	assert.Equal(constants.CoordinatorName, rootCert.Subject.CommonName)

	cert, err := c.GetTLSRootCertificate(&tls.ClientHelloInfo{})
	assert.NoError(err)
	assert.NotNil(cert)

	config, err := c.GetTLSConfig()
	assert.NoError(err)
	assert.NotNil(config)
}

func TestSeal(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	ctx := context.Background()

	zapLogger := zaptest.NewLogger(t)

	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	fs := afero.NewMemMapFs()
	store := stdstore.New(sealer, stubEnabler{}, fs, "", zapLogger)
	recovery := recovery.New(store, zapLogger)

	c, err := NewCore([]string{"localhost"}, validator, issuer, store, recovery, zapLogger, nil, nil)
	require.NoError(err)

	// Set manifest. This will seal the state.
	clientAPI, err := clientapi.New(store, c.recovery, c, &distributor.Stub{}, stubEnabler{}, zapLogger)
	require.NoError(err)
	_, err = clientAPI.SetManifest(ctx, []byte(test.ManifestJSON))
	require.NoError(err)

	// Get certificate and signature.
	cert, err := c.GetTLSRootCertificate(&tls.ClientHelloInfo{})
	assert.NoError(err)
	signatureRootECDSA, signature, _ := clientAPI.GetManifestSignature(ctx)

	// Get secrets
	cSecrets := testutil.GetSecretMap(t, c.txHandle)

	// Check sealing with a new core initialized with the sealed state.
	store2 := stdstore.New(sealer, stubEnabler{}, fs, "", zapLogger)
	c2, err := NewCore([]string{"localhost"}, validator, issuer, store2, recovery, zapLogger, nil, nil)
	require.NoError(err)
	clientAPI, err = clientapi.New(store2, c2.recovery, c2, &distributor.Stub{}, stubEnabler{}, zapLogger)
	require.NoError(err)
	c2State := testutil.GetState(t, c2.txHandle)
	assert.Equal(state.AcceptingMarbles, c2State)

	cert2, err := c2.GetTLSRootCertificate(&tls.ClientHelloInfo{})
	assert.NoError(err)
	assert.Equal(cert, cert2)

	_, err = clientAPI.SetManifest(ctx, []byte(test.ManifestJSON))
	assert.Error(err)

	// Check if the secret specified in the test manifest is unsealed correctly
	c2Secrets := testutil.GetSecretMap(t, c2.txHandle)
	assert.Equal(cSecrets, c2Secrets)

	signatureRootECDSA2, signature2, _ := clientAPI.GetManifestSignature(ctx)
	assert.Equal(signature, signature2, "manifest signature differs after restart")
	assert.Equal(signatureRootECDSA, signatureRootECDSA2, "manifest signature root ecdsa differs after restart")
}

func TestRecover(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	ctx := context.Background()

	zapLogger := zaptest.NewLogger(t)

	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	fs := afero.NewMemMapFs()
	store := stdstore.New(sealer, stubEnabler{}, fs, "", zapLogger)
	recovery := recovery.New(store, zapLogger)

	c, err := NewCore([]string{"localhost"}, validator, issuer, store, recovery, zapLogger, nil, nil)
	require.NoError(err)
	clientAPI, err := clientapi.New(store, c.recovery, c, &distributor.Stub{}, stubEnabler{}, zapLogger)
	require.NoError(err)

	// new core does not allow recover
	key, sig := recoveryKeyWithSignature(t, test.RecoveryPrivateKeyOne)
	_, err = clientAPI.Recover(ctx, key, sig)
	assert.Error(err)

	// Set manifest. This will seal the state.
	_, err = clientAPI.SetManifest(ctx, []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)

	// core does not allow recover after manifest has been set
	_, err = clientAPI.Recover(ctx, key, sig)
	assert.Error(err)

	// Initialize new core and let unseal fail
	sealer.UnsealError = &seal.EncryptionKeyError{}
	store2 := stdstore.New(sealer, stubEnabler{}, fs, "", zapLogger)
	c2, err := NewCore([]string{"localhost"}, validator, issuer, store2, recovery, zapLogger, nil, nil)
	sealer.UnsealError = nil
	require.NoError(err)
	clientAPI, err = clientapi.New(store2, c2.recovery, c2, &distributor.Stub{}, stubEnabler{}, zapLogger)
	require.NoError(err)
	c2State := testutil.GetState(t, c2.txHandle)
	require.Equal(state.Recovery, c2State)

	// recover
	_, err = clientAPI.Recover(ctx, key, sig)
	assert.NoError(err)
	c2State = testutil.GetState(t, c2.txHandle)
	assert.Equal(state.AcceptingMarbles, c2State)
}

func TestGenerateSecrets(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Some secret maps which should represent secret entries from an unmarshaled JSON manifest
	secretsToGenerate := map[string]manifest.Secret{
		"rawTest1":                {Type: manifest.SecretTypeSymmetricKey, Size: 128, Shared: true},
		"rawTest2":                {Type: manifest.SecretTypeSymmetricKey, Size: 256, Shared: true},
		"cert-rsa-test":           {Type: manifest.SecretTypeCertRSA, Size: 2048, ValidFor: 365, Shared: true},
		"cert-ed25519-test":       {Type: manifest.SecretTypeCertED25519, Shared: true},
		"cert-ecdsa224-test":      {Type: manifest.SecretTypeCertECDSA, Size: 224, ValidFor: 14, Shared: true},
		"cert-ecdsa256-test":      {Type: manifest.SecretTypeCertECDSA, Size: 256, ValidFor: 14, Shared: true},
		"cert-ecdsa384-test":      {Type: manifest.SecretTypeCertECDSA, Size: 384, ValidFor: 14, Shared: true},
		"cert-ecdsa521-test":      {Type: manifest.SecretTypeCertECDSA, Size: 521, ValidFor: 14, Shared: true},
		"cert-rsa-specified-test": {Type: manifest.SecretTypeCertRSA, Size: 2048, Cert: manifest.Certificate{}, Shared: true},
		"cert-ed25519-ca-test":    {Type: manifest.SecretTypeCertED25519, Cert: manifest.Certificate{IsCA: true}, Shared: true},
	}

	secretsNoSize := map[string]manifest.Secret{
		"noSize": {Type: manifest.SecretTypeSymmetricKey, Shared: true},
	}

	secretsInvalidType := map[string]manifest.Secret{
		"unknownType": {Type: "crap", Shared: true},
	}

	secretsEd25519WrongKeySize := map[string]manifest.Secret{
		"cert-ed25519-invalidsize": {Type: manifest.SecretTypeCertED25519, Size: 384, Shared: true},
	}

	secretsECDSAWrongKeySize := map[string]manifest.Secret{
		"cert-ecdsa-invalidsize": {Type: manifest.SecretTypeCertECDSA, Size: 512, Shared: true},
	}

	secretsEmptyMap := map[string]manifest.Secret{}

	c := newCoreWithMocks()

	rootCert := testutil.GetCertificate(t, c.txHandle, constants.SKCoordinatorRootCert)
	rootPrivK := testutil.GetPrivateKey(t, c.txHandle, constants.SKCoordinatorRootKey)

	// This should return valid secrets
	generatedSecrets, err := c.GenerateSecrets(secretsToGenerate, uuid.Nil, "", rootCert, rootPrivK, rootPrivK)
	require.NoError(err)
	// Check if rawTest1 has 128 Bits/16 Bytes and rawTest2 256 Bits/8 Bytes
	assert.Len(generatedSecrets["rawTest1"].Public, 16)
	assert.Len(generatedSecrets["rawTest2"].Public, 32)
	assert.NotNil(generatedSecrets["cert-rsa-test"].Cert.Raw)
	assert.NotNil(generatedSecrets["cert-ed25519-test"].Cert.Raw)
	assert.NotNil(generatedSecrets["cert-ecdsa224-test"].Cert.Raw)
	assert.NotNil(generatedSecrets["cert-ecdsa256-test"].Cert.Raw)
	assert.NotNil(generatedSecrets["cert-ecdsa384-test"].Cert.Raw)
	assert.NotNil(generatedSecrets["cert-ecdsa521-test"].Cert.Raw)
	assert.NotNil(generatedSecrets["cert-rsa-specified-test"].Cert.Raw)
	assert.NotNil(generatedSecrets["cert-ed25519-ca-test"].Cert.Raw)

	// If unspecified, CN and DNS names should be set to localhost
	assert.Equal("localhost", generatedSecrets["cert-rsa-test"].Cert.Subject.CommonName)
	assert.Equal([]string{"localhost"}, generatedSecrets["cert-rsa-test"].Cert.DNSNames)

	// Make sure a certificate gets a new serial number if its regenerated
	firstSerial := generatedSecrets["cert-rsa-test"].Cert.SerialNumber
	secondGeneration, err := c.GenerateSecrets(generatedSecrets, uuid.Nil, "", rootCert, rootPrivK, rootPrivK)
	assert.NoError(err)
	assert.NotEqualValues(*firstSerial, *secondGeneration["cert-rsa-test"].Cert.SerialNumber)

	// Check if CA certificate can generate another certificate
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(err)
	template := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			Organization: []string{"Test leaf signed by Coordinator"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
	}
	secretCACert := x509.Certificate(generatedSecrets["cert-ed25519-ca-test"].Cert)
	secretCAPriv, err := x509.ParsePKCS8PrivateKey(generatedSecrets["cert-ed25519-ca-test"].Private)
	require.NoError(err)

	leafFromSecret, err := x509.CreateCertificate(rand.Reader, &template, &secretCACert, pub, secretCAPriv)
	assert.NoError(err)
	assert.NotNil(leafFromSecret)

	// Check if we can verify the certificate based on the root CA of the coordinator and the intermediate CA secret certificate
	leafFromSecretCert, err := x509.ParseCertificate(leafFromSecret)
	assert.NoError(err)
	assert.NotNil(leafFromSecretCert)

	roots := x509.NewCertPool()
	intermediate := x509.NewCertPool()
	roots.AddCert(rootCert)
	intermediate.AddCert(&secretCACert)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediate,
	}

	_, err = leafFromSecretCert.Verify(opts)
	assert.NoError(err)

	// Check if we get an empty secret map as output for an empty map as input
	generatedSecrets, err = c.GenerateSecrets(secretsEmptyMap, uuid.Nil, "", rootCert, rootPrivK, rootPrivK)
	require.NoError(err)
	assert.IsType(map[string]manifest.Secret{}, generatedSecrets)
	assert.Len(generatedSecrets, 0)

	// Check if we get an empty secret map as output for nil
	generatedSecrets, err = c.GenerateSecrets(nil, uuid.Nil, "", rootCert, rootPrivK, rootPrivK)
	require.NoError(err)
	assert.IsType(map[string]manifest.Secret{}, generatedSecrets)
	assert.Len(generatedSecrets, 0)

	// If no size is specified, the function should fail
	_, err = c.GenerateSecrets(secretsNoSize, uuid.Nil, "", rootCert, rootPrivK, rootPrivK)
	assert.Error(err)

	// Also, it should fail if we try to generate a secret with an unknown type
	_, err = c.GenerateSecrets(secretsInvalidType, uuid.Nil, "", rootCert, rootPrivK, rootPrivK)
	assert.Error(err)

	// If Ed25519 key size is specified, we should fail
	_, err = c.GenerateSecrets(secretsEd25519WrongKeySize, uuid.Nil, "", rootCert, rootPrivK, rootPrivK)
	assert.Error(err)

	// However, for ECDSA we fail as we can have multiple curves
	_, err = c.GenerateSecrets(secretsECDSAWrongKeySize, uuid.Nil, "", rootCert, rootPrivK, rootPrivK)
	assert.Error(err)
}

func TestUnsetRestart(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	zapLogger := zaptest.NewLogger(t)
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	fs := afero.NewMemMapFs()
	store := stdstore.New(sealer, stubEnabler{}, fs, "", zapLogger)
	recovery := recovery.New(store, zapLogger)

	// create a new core, this seals the state with only certificate and keys
	c1, err := NewCore([]string{"localhost"}, validator, issuer, store, recovery, zapLogger, nil, nil)
	require.NoError(err)
	c1State := testutil.GetState(t, c1.txHandle)
	assert.Equal(state.AcceptingManifest, c1State)
	cCert := testutil.GetCertificate(t, c1.txHandle, constants.SKCoordinatorRootCert)

	// create a second core, this should overwrite the previously sealed certificate and keys since no manifest was set
	c2, err := NewCore([]string{"localhost"}, validator, issuer, stdstore.New(sealer, stubEnabler{}, fs, "", zapLogger), recovery, zapLogger, nil, nil)
	require.NoError(err)
	c2State := testutil.GetState(t, c2.txHandle)
	assert.Equal(state.AcceptingManifest, c2State)
	c2Cert := testutil.GetCertificate(t, c2.txHandle, constants.SKCoordinatorRootCert)
	assert.NotEqual(*cCert, *c2Cert)
}

func TestGetQuote(t *testing.T) {
	testCases := map[string]struct {
		reportData []byte
		savedQuote []byte
		issuer     stubIssuer
		wantErr    bool
	}{
		"no report data": {
			reportData: nil,
			savedQuote: []byte("quote"),
			issuer:     stubIssuer{},
		},
		"with report data": {
			reportData: []byte("report data"),
			savedQuote: []byte("quote"),
			issuer:     stubIssuer{},
		},
		"issuer error": {
			reportData: []byte("report data"),
			savedQuote: []byte("quote"),
			issuer:     stubIssuer{err: assert.AnError},
			wantErr:    true,
		},
		"OE_UNSUPPORTED error is ignored": {
			issuer: stubIssuer{err: errors.New("OE_UNSUPPORTED")},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			zapLogger := zaptest.NewLogger(t)
			core := Core{
				qi:    &tc.issuer,
				log:   zapLogger,
				quote: tc.savedQuote,
			}

			quote, err := core.GetQuote(tc.reportData)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			if len(tc.reportData) == 0 {
				assert.Equal(tc.savedQuote, quote)
			} else {
				assert.Equal(tc.reportData, quote) // stubIssuer returns the input message as quote
			}
		})
	}
}

// newCoreWithMocks creates a new core object with quote and seal mocks for testing.
func newCoreWithMocks() *Core {
	zapLogger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}

	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	store := stdstore.New(sealer, stubEnabler{}, afero.Afero{Fs: afero.NewMemMapFs()}, "", zapLogger)
	recovery := recovery.New(store, zapLogger)
	core, err := NewCore([]string{"localhost"}, validator, issuer, store, recovery, zapLogger, nil, nil)
	if err != nil {
		panic(err)
	}
	return core
}

type stubIssuer struct {
	err error
}

func (s *stubIssuer) Issue(message []byte) ([]byte, error) {
	return message, s.err
}

func recoveryKeyWithSignature(t *testing.T, priv *rsa.PrivateKey) ([]byte, []byte) {
	t.Helper()
	key := make([]byte, 16)
	sig, err := util.SignPKCS1v15(priv, key)
	require.NoError(t, err)
	return key, sig
}

type stubEnabler struct{}

func (stubEnabler) SetEnabled(_ bool) {}
