// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/user"
	"github.com/edgelesssys/marblerun/test"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestCore(t *testing.T) {
	assert := assert.New(t)

	c := NewCoreWithMocks()
	curState, err := c.data.getState()
	assert.NoError(err)
	assert.Equal(stateAcceptingManifest, curState)
	rootCert, err := c.data.getCertificate(sKCoordinatorRootCert)
	assert.NoError(err)
	assert.Equal(coordinatorName, rootCert.Subject.CommonName)

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
	sealer := &seal.MockSealer{}
	recovery := recovery.NewSinglePartyRecovery()

	c, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger, nil, nil)
	require.NoError(err)

	// Set manifest. This will seal the state.
	_, err = c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	require.NoError(err)

	// Get certificate and signature.
	cert, err := c.GetTLSRootCertificate(nil)
	assert.NoError(err)
	signatureRootECDSA, signature, _ := c.GetManifestSignature(context.TODO())

	// Get secrets
	cSecrets, err := c.data.getSecretMap()
	assert.NoError(err)

	// Check sealing with a new core initialized with the sealed state.
	c2, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger, nil, nil)
	require.NoError(err)
	c2State, err := c2.data.getState()
	assert.NoError(err)
	assert.Equal(stateAcceptingMarbles, c2State)

	cert2, err := c2.GetTLSRootCertificate(nil)
	assert.NoError(err)
	assert.Equal(cert, cert2)

	_, err = c2.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	assert.Error(err)

	// Check if the secret specified in the test manifest is unsealed correctly
	c2Secrets, err := c2.data.getSecretMap()
	assert.NoError(err)
	assert.Equal(cSecrets, c2Secrets)

	signatureRootECDSA2, signature2, _ := c2.GetManifestSignature(context.TODO())
	assert.Equal(signature, signature2, "manifest signature differs after restart")
	assert.Equal(signatureRootECDSA, signatureRootECDSA2, "manifest signature root ecdsa differs after restart")
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
	sealer := &seal.MockSealer{}
	recovery := recovery.NewSinglePartyRecovery()

	c, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger, nil, nil)
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
	sealer.UnsealError = seal.ErrEncryptionKey
	c2, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger, nil, nil)
	sealer.UnsealError = nil
	require.NoError(err)
	c2State, err := c2.data.getState()
	assert.NoError(err)
	require.Equal(stateRecovery, c2State)

	// recover
	_, err = c2.Recover(context.TODO(), key)
	assert.NoError(err)
	c2State, err = c2.data.getState()
	assert.NoError(err)
	assert.Equal(stateAcceptingMarbles, c2State)
}

func TestGenerateUsersFromManifest(t *testing.T) {
	assert := assert.New(t)

	Users := map[string]manifest.User{
		"Alice": {
			Certificate: string(test.AdminCert),
			Roles:       []string{"writeRole", "readRole"},
		},
		"Bob": {
			Certificate: string(test.AdminCert),
			Roles:       []string{"writeRole", "updateRole"},
		},
	}
	Roles := map[string]manifest.Role{
		"writeRole": {
			ResourceType:  "Secrets",
			ResourceNames: []string{"secretOne"},
			Actions:       []string{"WriteSecret"},
		},
		"readRole": {
			ResourceType:  "Secrets",
			ResourceNames: []string{"secretOne", "secretTwo"},
			Actions:       []string{"readsecret"},
		},
		"updateRole": {
			ResourceType:  "Packages",
			ResourceNames: []string{"frontend", "backend"},
			Actions:       []string{"UpdateSecurityVersion"},
		},
	}
	newUsers, err := generateUsersFromManifest(Users, Roles)
	assert.NoError(err)
	assert.Equal(len(Users), len(newUsers))
	for _, newUser := range newUsers {
		switch newUser.Name() {
		case "Alice":
			assert.True(newUser.IsGranted(user.NewPermission(user.PermissionWriteSecret, []string{"secretOne"})))
			assert.True(newUser.IsGranted(user.NewPermission(user.PermissionReadSecret, []string{"secretOne", "secretTwo"})))
			assert.False(newUser.IsGranted(user.NewPermission(user.PermissionUpdatePackage, []string{"frontend", "backend"})))
		case "Bob":
			assert.True(newUser.IsGranted(user.NewPermission(user.PermissionWriteSecret, []string{"secretOne"})))
			assert.False(newUser.IsGranted(user.NewPermission(user.PermissionReadSecret, []string{"secretOne", "secretTwo"})))
			assert.True(newUser.IsGranted(user.NewPermission(user.PermissionUpdatePackage, []string{"frontend", "backend"})))
		}
	}

	// try to generate new users with missing certificate, this should always error
	invalidUsers := map[string]manifest.User{
		"Alice": {
			Roles: []string{"writeRole"},
		},
		"Bob": {
			Certificate: string(test.AdminCert),
			Roles:       []string{"updateRole"},
		},
	}
	_, err = generateUsersFromManifest(invalidUsers, Roles)
	assert.Error(err)
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
		"cert-ed25519-ca-test":    {Type: "cert-ed25519", Cert: manifest.Certificate{IsCA: true}, Shared: true},
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

	rootCert, err := c.data.getCertificate(sKCoordinatorRootCert)
	assert.NoError(err)
	rootPrivK, err := c.data.getPrivK(sKCoordinatorRootKey)
	assert.NoError(err)

	// This should return valid secrets
	generatedSecrets, err := c.generateSecrets(context.TODO(), secretsToGenerate, uuid.Nil, rootCert, rootPrivK)
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
	secondGeneration, err := c.generateSecrets(context.TODO(), generatedSecrets, uuid.Nil, rootCert, rootPrivK)
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
	generatedSecrets, err = c.generateSecrets(context.TODO(), secretsEmptyMap, uuid.Nil, rootCert, rootPrivK)
	require.NoError(err)
	assert.IsType(map[string]manifest.Secret{}, generatedSecrets)
	assert.Len(generatedSecrets, 0)

	// Check if we get an empty secret map as output for nil
	generatedSecrets, err = c.generateSecrets(context.TODO(), nil, uuid.Nil, rootCert, rootPrivK)
	require.NoError(err)
	assert.IsType(map[string]manifest.Secret{}, generatedSecrets)
	assert.Len(generatedSecrets, 0)

	// If no size is specified, the function should fail
	_, err = c.generateSecrets(context.TODO(), secretsNoSize, uuid.Nil, rootCert, rootPrivK)
	assert.Error(err)

	// Also, it should fail if we try to generate a secret with an unknown type
	_, err = c.generateSecrets(context.TODO(), secretsInvalidType, uuid.Nil, rootCert, rootPrivK)
	assert.Error(err)

	// If Ed25519 key size is specified, we should fail
	_, err = c.generateSecrets(context.TODO(), secretsEd25519WrongKeySize, uuid.Nil, rootCert, rootPrivK)
	assert.Error(err)

	// However, for ECDSA we fail as we can have multiple curves
	_, err = c.generateSecrets(context.TODO(), secretsECDSAWrongKeySize, uuid.Nil, rootCert, rootPrivK)
	assert.Error(err)
}

func TestUnsetRestart(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	zapLogger, err := zap.NewDevelopment()
	require.NoError(err)
	defer zapLogger.Sync()
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	recovery := recovery.NewSinglePartyRecovery()

	// create a new core, this seals the state with only certificate and keys
	c1, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger, nil, nil)
	require.NoError(err)
	c1State, err := c1.data.getState()
	assert.NoError(err)
	assert.Equal(stateAcceptingManifest, c1State)
	cCert, err := c1.data.getCertificate(sKCoordinatorRootCert)
	assert.NoError(err)

	// create a second core, this should overwrite the previously sealed certificate and keys since no manifest was set
	c2, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger, nil, nil)
	require.NoError(err)
	c2State, err := c2.data.getState()
	assert.NoError(err)
	assert.Equal(stateAcceptingManifest, c2State)
	c2Cert, err := c2.data.getCertificate(sKCoordinatorRootCert)
	assert.NoError(err)

	assert.NotEqual(*cCert, *c2Cert)
}
