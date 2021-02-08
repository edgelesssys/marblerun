// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"context"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/test"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestCore(t *testing.T) {
	assert := assert.New(t)

	c := NewCoreWithMocks()
	assert.Equal(stateAcceptingManifest, c.state)
	assert.Equal(coordinatorName, c.rootCert.Subject.CommonName)

	cert, err := c.GetTLSRootCertificate(nil)
	assert.NoError(err)
	assert.NotNil(cert)

	config, err := c.GetTLSConfig()
	assert.NoError(err)
	assert.NotNil(config)

	manifest := []byte(test.ManifestJSON)
	// try to set broken manifest
	_, err = c.SetManifest(context.TODO(), manifest[:len(manifest)-1])
	assert.Error(err)
	// set manifest
	_, err = c.SetManifest(context.TODO(), manifest)
	assert.NoError(err)
	// set manifest a second time
	_, err = c.SetManifest(context.TODO(), manifest)
	assert.Error(err)
}

func TestSeal(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// setup mock zaplogger which can be passed to Core
	zapLogger, err := zap.NewDevelopment()
	require.NoError(err)
	defer zapLogger.Sync()

	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &MockSealer{}
	recovery := recovery.NewSinglePartyRecovery()

	c, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger)
	require.NoError(err)

	// Set manifest. This will seal the state.
	_, err = c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	require.NoError(err)

	// Get certificate and signature.
	cert, err := c.GetTLSRootCertificate(nil)
	assert.NoError(err)
	signature := c.GetManifestSignature(context.TODO())

	// Check sealing with a new core initialized with the sealed state.
	c2, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger)
	require.NoError(err)
	assert.Equal(stateAcceptingMarbles, c2.state)

	cert2, err := c2.GetTLSRootCertificate(nil)
	assert.NoError(err)
	assert.Equal(cert, cert2)

	_, err = c2.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	assert.Error(err)

	// Check if the secret specified in the test manifest is unsealed correctly
	assert.Equal(c.secrets, c2.secrets)

	signature2 := c2.GetManifestSignature(context.TODO())
	assert.Equal(signature, signature2, "manifest signature differs after restart")
}

func TestRecover(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// setup mock zaplogger which can be passed to Core
	zapLogger, err := zap.NewDevelopment()
	require.NoError(err)
	defer zapLogger.Sync()

	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &MockSealer{}
	recovery := recovery.NewSinglePartyRecovery()

	c, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger)
	require.NoError(err)

	// new core does not allow recover
	key := make([]byte, 16)
	_, err = c.Recover(context.TODO(), key)
	assert.Error(err)

	// Set manifest. This will seal the state.
	_, err = c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	require.NoError(err)

	// core does not allow recover after manifest has been set
	_, err = c.Recover(context.TODO(), key)
	assert.Error(err)

	// Initialize new core and let unseal fail
	sealer.unsealError = ErrEncryptionKey
	c2, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger)
	sealer.unsealError = nil
	require.NoError(err)
	require.Equal(stateRecovery, c2.state)

	// recover
	_, err = c2.Recover(context.TODO(), key)
	assert.NoError(err)
	assert.Equal(stateAcceptingMarbles, c2.state)
}

func TestGenerateSecrets(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Some secret maps which should represent secret entries from an unmarshaled JSON manifest
	secretsToGenerate := map[string]manifest.Secret{
		"rawTest1":                {Type: "symmetric-key", Size: 128, Shared: true},
		"rawTest2":                {Type: "symmetric-key", Size: 256, Shared: true},
		"cert-rsa-test":           {Type: "cert-rsa", Size: 2048, ValidFor: 365, Shared: true},
		"cert-ed25519-test":       {Type: "cert-ed25519", Shared: true},
		"cert-ecdsa224-test":      {Type: "cert-ecdsa", Size: 224, ValidFor: 14, Shared: true},
		"cert-ecdsa256-test":      {Type: "cert-ecdsa", Size: 256, ValidFor: 14, Shared: true},
		"cert-ecdsa384-test":      {Type: "cert-ecdsa", Size: 384, ValidFor: 14, Shared: true},
		"cert-ecdsa521-test":      {Type: "cert-ecdsa", Size: 521, ValidFor: 14, Shared: true},
		"cert-rsa-specified-test": {Type: "cert-rsa", Size: 2048, Cert: manifest.Certificate{}, Shared: true},
	}

	secretsNoSize := map[string]manifest.Secret{
		"noSize": {Type: "symmetric-key", Shared: true},
	}

	secretsInvalidType := map[string]manifest.Secret{
		"unknownType": {Type: "crap", Shared: true},
	}

	secretsEd25519WrongKeySize := map[string]manifest.Secret{
		"cert-ed25519-invalidsize": {Type: "cert-ed25519", Size: 384, Shared: true},
	}

	secretsECDSAWrongKeySize := map[string]manifest.Secret{
		"cert-ecdsa-invalidsize": {Type: "cert-ecdsa", Size: 512, Shared: true},
	}

	secretsEmptyMap := map[string]manifest.Secret{}

	c := NewCoreWithMocks()

	// This should return valid secrets
	generatedSecrets, err := c.generateSecrets(context.TODO(), secretsToGenerate, uuid.Nil, c.rootCert, c.rootPrivK)
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

	// Check if we get an empty secret map as output for an empty map as input
	generatedSecrets, err = c.generateSecrets(context.TODO(), secretsEmptyMap, uuid.Nil, c.rootCert, c.rootPrivK)
	assert.IsType(map[string]manifest.Secret{}, generatedSecrets)
	assert.Len(generatedSecrets, 0)

	// Check if we get an empty secret map as output for nil
	generatedSecrets, err = c.generateSecrets(context.TODO(), nil, uuid.Nil, c.rootCert, c.rootPrivK)
	assert.IsType(map[string]manifest.Secret{}, generatedSecrets)
	assert.Len(generatedSecrets, 0)

	// If no size is specified, the function should fail
	_, err = c.generateSecrets(context.TODO(), secretsNoSize, uuid.Nil, c.rootCert, c.rootPrivK)
	assert.Error(err)

	// Also, it should fail if we try to generate a secret with an unknown type
	_, err = c.generateSecrets(context.TODO(), secretsInvalidType, uuid.Nil, c.rootCert, c.rootPrivK)
	assert.Error(err)

	// If Ed25519 key size is specified, we should fail
	_, err = c.generateSecrets(context.TODO(), secretsEd25519WrongKeySize, uuid.Nil, c.rootCert, c.rootPrivK)
	assert.Error(err)

	// However, for ECDSA we fail as we can have multiple curves
	_, err = c.generateSecrets(context.TODO(), secretsECDSAWrongKeySize, uuid.Nil, c.rootCert, c.rootPrivK)
	assert.Error(err)
}
