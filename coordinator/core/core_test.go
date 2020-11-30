// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"context"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestCore(t *testing.T) {
	assert := assert.New(t)

	c := NewCoreWithMocks()
	assert.Equal(stateAcceptingManifest, c.state)
	assert.Equal(CoordinatorName, c.cert.Subject.CommonName)

	cert, err := c.GetTLSCertificate(nil)
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

	c, err := NewCore([]string{"localhost"}, validator, issuer, sealer, zapLogger)
	require.NoError(err)

	// Set manifest. This will seal the state.
	_, err = c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	require.NoError(err)

	// Get certificate and signature.
	cert, err := c.GetTLSCertificate(nil)
	assert.NoError(err)
	signature := c.GetManifestSignature(context.TODO())

	// Check sealing with a new core initialized with the sealed state.
	c2, err := NewCore([]string{"localhost"}, validator, issuer, sealer, zapLogger)
	require.NoError(err)
	assert.Equal(stateAcceptingMarbles, c2.state)

	cert2, err := c2.GetTLSCertificate(nil)
	assert.NoError(err)
	assert.Equal(cert, cert2)

	_, err = c2.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	assert.Error(err)

	// Check if the secret specified in the test manifest is unsealed correctly
	assert.IsType(Secret{}, c.secrets["testsecret_raw"])
	assert.Len(c.secrets["testsecret_raw"].Public, 16)
	assert.Len(c.secrets["testsecret_raw"].Private, 16)

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

	c, err := NewCore([]string{"localhost"}, validator, issuer, sealer, zapLogger)
	require.NoError(err)

	// new core does not allow recover
	key := make([]byte, 16)
	assert.Error(c.Recover(context.TODO(), key))

	// Set manifest. This will seal the state.
	_, err = c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	require.NoError(err)

	// core does not allow recover after manifest has been set
	assert.Error(c.Recover(context.TODO(), key))

	// Initialize new core and let unseal fail
	sealer.unsealError = ErrEncryptionKey
	c2, err := NewCore([]string{"localhost"}, validator, issuer, sealer, zapLogger)
	sealer.unsealError = nil
	require.NoError(err)
	require.Equal(stateRecovery, c2.state)

	// recover
	assert.NoError(c2.Recover(context.TODO(), key))
	assert.Equal(stateAcceptingMarbles, c2.state)
}

func TestGenerateSecrets(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Some secret maps which should represent secret entries from an unmarshaled JSON manifest
	secretsToGenerate := map[string]Secret{
		"rawTest1": {Type: "raw", Size: 128},
		"rawTest2": {Type: "raw", Size: 256},
	}

	secretsNoSize := map[string]Secret{
		"noSize": {Type: "raw"},
	}

	secretsInvalidType := map[string]Secret{
		"unknownType": {Type: "crap"},
	}

	secretsEmptyMap := map[string]Secret{}

	c := NewCoreWithMocks()

	// This should return valid secrets
	generatedSecrets, err := c.generateSecrets(context.TODO(), secretsToGenerate)
	require.NoError(err)
	// Check if rawTest1 has 128 Bits/16 Bytes and rawTest2 256 Bits/8 Bytes
	assert.Len(generatedSecrets["rawTest1"].Public, 16)
	assert.Len(generatedSecrets["rawTest2"].Public, 32)

	// Check if we get an empty secret map as output for an empty map as input
	generatedSecrets, err = c.generateSecrets(context.TODO(), secretsEmptyMap)
	assert.IsType(map[string]Secret{}, generatedSecrets)
	assert.Len(generatedSecrets, 0)

	// Check if we get an empty secret map as output for nil
	generatedSecrets, err = c.generateSecrets(context.TODO(), nil)
	assert.IsType(map[string]Secret{}, generatedSecrets)
	assert.Len(generatedSecrets, 0)

	// If no size is specified, the function should fail
	_, err = c.generateSecrets(context.TODO(), secretsNoSize)
	assert.Error(err)

	// Also, it should fail if we try to generate a secret with an unknown type
	_, err = c.generateSecrets(context.TODO(), secretsInvalidType)
	assert.Error(err)
}
