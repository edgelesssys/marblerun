// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package clientapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/crypto"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/zap"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestGetCertQuote(t *testing.T) {
	someErr := errors.New("failed")

	testCases := map[string]struct {
		storeWrapper *stubStoreWrapper
		core         *fakeCore
		wantErr      bool
	}{
		"success state accepting Marbles": {
			storeWrapper: &stubStoreWrapper{
				getCertificateList: map[string]*x509.Certificate{
					constants.SKCoordinatorRootCert:         {Raw: []byte("root")},
					constants.SKCoordinatorIntermediateCert: {Raw: []byte("intermediate")},
				},
			},
			core: &fakeCore{
				state: state.AcceptingMarbles,
				quote: []byte("quote"),
			},
		},
		"success state accepting manifest": {
			storeWrapper: &stubStoreWrapper{
				getCertificateList: map[string]*x509.Certificate{
					constants.SKCoordinatorRootCert:         {Raw: []byte("root")},
					constants.SKCoordinatorIntermediateCert: {Raw: []byte("intermediate")},
				},
			},
			core: &fakeCore{
				state: state.AcceptingManifest,
				quote: []byte("quote"),
			},
		},
		"success state recovery": {
			storeWrapper: &stubStoreWrapper{
				getCertificateList: map[string]*x509.Certificate{
					constants.SKCoordinatorRootCert:         {Raw: []byte("root")},
					constants.SKCoordinatorIntermediateCert: {Raw: []byte("intermediate")},
				},
			},
			core: &fakeCore{
				state: state.Recovery,
				quote: []byte("quote"),
			},
		},
		"unsupported state": {
			storeWrapper: &stubStoreWrapper{
				getCertificateList: map[string]*x509.Certificate{
					constants.SKCoordinatorRootCert:         {Raw: []byte("root")},
					constants.SKCoordinatorIntermediateCert: {Raw: []byte("intermediate")},
				},
			},
			core: &fakeCore{
				state: state.Uninitialized,
				quote: []byte("quote"),
			},
			wantErr: true,
		},
		"error getting state": {
			storeWrapper: &stubStoreWrapper{
				getCertificateList: map[string]*x509.Certificate{
					constants.SKCoordinatorRootCert:         {Raw: []byte("root")},
					constants.SKCoordinatorIntermediateCert: {Raw: []byte("intermediate")},
				},
			},
			core: &fakeCore{
				requireStateErr: someErr,
				quote:           []byte("quote"),
			},
			wantErr: true,
		},
		"empty root cert": {
			storeWrapper: &stubStoreWrapper{
				getCertificateList: map[string]*x509.Certificate{
					constants.SKCoordinatorRootCert:         nil,
					constants.SKCoordinatorIntermediateCert: {Raw: []byte("intermediate")},
				},
			},
			core: &fakeCore{
				state: state.AcceptingMarbles,
				quote: []byte("quote"),
			},
			wantErr: true,
		},
		"empty intermediate cert": {
			storeWrapper: &stubStoreWrapper{
				getCertificateList: map[string]*x509.Certificate{
					constants.SKCoordinatorRootCert:         {Raw: []byte("root")},
					constants.SKCoordinatorIntermediateCert: nil,
				},
			},
			core: &fakeCore{
				state: state.AcceptingMarbles,
				quote: []byte("quote"),
			},
			wantErr: true,
		},
		"root certificate not set": {
			storeWrapper: &stubStoreWrapper{
				getCertificateList: map[string]*x509.Certificate{
					constants.SKCoordinatorIntermediateCert: {Raw: []byte("intermediate")},
				},
			},
			core: &fakeCore{
				state: state.AcceptingMarbles,
				quote: []byte("quote"),
			},
			wantErr: true,
		},
		"intermediate certificate not set": {
			storeWrapper: &stubStoreWrapper{
				getCertificateList: map[string]*x509.Certificate{
					constants.SKCoordinatorRootCert: {Raw: []byte("root")},
				},
			},
			core: &fakeCore{
				state: state.AcceptingMarbles,
				quote: []byte("quote"),
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			log, err := zap.NewDevelopment()
			require.NoError(err)
			defer func() { _ = log.Sync() }()

			api := &ClientAPI{
				core: tc.core,
				data: tc.storeWrapper,
				log:  log,
			}

			cert, quote, err := api.GetCertQuote()
			if tc.wantErr {
				assert.Error(err)
				return
			}

			require.NoError(err)
			assert.Equal(tc.core.quote, quote)
			intermediateCert := tc.storeWrapper.getCertificateList[constants.SKCoordinatorIntermediateCert]
			rootCert := tc.storeWrapper.getCertificateList[constants.SKCoordinatorRootCert]
			assert.Equal(mustEncodeToPem(t, intermediateCert)+mustEncodeToPem(t, rootCert), cert)
		})
	}
}

func TestGetManifestSignature(t *testing.T) {
	someErr := errors.New("failed")

	testCases := map[string]struct {
		data    *stubStoreWrapper
		wantErr bool
	}{
		"success": {
			data: &stubStoreWrapper{
				rawManifest:       []byte("manifest"),
				manifestSignature: []byte("signature"),
			},
		},
		"GetRawManifest fails": {
			data: &stubStoreWrapper{
				getRawManifestErr: someErr,
				manifestSignature: []byte("signature"),
			},
			wantErr: true,
		},
		"GetManifestSignature fails": {
			data: &stubStoreWrapper{
				rawManifest:             []byte("manifest"),
				getManifestSignatureErr: someErr,
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			log, err := zap.NewDevelopment()
			require.NoError(err)
			defer func() { _ = log.Sync() }()

			api := &ClientAPI{
				data: tc.data,
				log:  log,
			}

			signature, hash, manifest := api.GetManifestSignature()
			if tc.wantErr {
				assert.Nil(signature)
				assert.Nil(hash)
				assert.Nil(manifest)
				return
			}
			assert.Equal(tc.data.rawManifest, manifest)
			expectedHash := sha256.Sum256(tc.data.rawManifest)
			assert.Equal(expectedHash[:], hash)
			assert.Equal(tc.data.manifestSignature, signature)
		})
	}
}

func TestGetSecrets(t *testing.T) {
	t.Log("WARNING: Missing unit Test for GetSecrets")
}

func TestGetStatus(t *testing.T) {
	t.Log("WARNING: Missing unit Test for GetStatus")
}

func TestGetUpdateLog(t *testing.T) {
	t.Log("WARNING: Missing unit Test for GetUpdateLog")
}

func TestRecover(t *testing.T) {
	someErr := errors.New("failed")

	testCases := map[string]struct {
		data     *stubStoreWrapper
		store    *stubStore
		recovery *stubRecovery
		core     *fakeCore
		wantErr  bool
	}{
		"success": {
			data: &stubStoreWrapper{
				getCertificateList: map[string]*x509.Certificate{
					constants.SKCoordinatorRootCert: {Raw: []byte("root cert")},
				},
			},
			store:    &stubStore{},
			recovery: &stubRecovery{},
			core: &fakeCore{
				state: state.Recovery,
			},
		},
		"more than one key required": {
			data: &stubStoreWrapper{
				getCertificateList: map[string]*x509.Certificate{
					constants.SKCoordinatorRootCert: {Raw: []byte("root cert")},
				},
			},
			store: &stubStore{},
			recovery: &stubRecovery{
				recoverKeysLeft: 1,
			},
			core: &fakeCore{
				state: state.Recovery,
			},
		},
		"SetRecoveryData fails does not result in error": {
			data: &stubStoreWrapper{
				getCertificateList: map[string]*x509.Certificate{
					constants.SKCoordinatorRootCert: {Raw: []byte("root cert")},
				},
			},
			store: &stubStore{},
			recovery: &stubRecovery{
				setRecoveryDataErr: someErr,
			},
			core: &fakeCore{
				state: state.Recovery,
			},
		},
		"Coordinator not in recovery state": {
			data: &stubStoreWrapper{
				getCertificateList: map[string]*x509.Certificate{
					constants.SKCoordinatorRootCert: {Raw: []byte("root cert")},
				},
			},
			store:    &stubStore{},
			recovery: &stubRecovery{},
			core: &fakeCore{
				state: state.AcceptingManifest,
			},
			wantErr: true,
		},
		"RecoverKey fails": {
			data: &stubStoreWrapper{
				getCertificateList: map[string]*x509.Certificate{
					constants.SKCoordinatorRootCert: {Raw: []byte("root cert")},
				},
			},
			store: &stubStore{},
			recovery: &stubRecovery{
				recoverKeyErr: someErr,
			},
			core: &fakeCore{
				state: state.Recovery,
			},
			wantErr: true,
		},
		"LoadState fails": {
			data: &stubStoreWrapper{
				getCertificateList: map[string]*x509.Certificate{
					constants.SKCoordinatorRootCert: {Raw: []byte("root cert")},
				},
			},
			store: &stubStore{
				loadStateErr: someErr,
			},
			recovery: &stubRecovery{},
			core: &fakeCore{
				state: state.Recovery,
			},
			wantErr: true,
		},
		"SetEncryptionKey fails": {
			data: &stubStoreWrapper{
				getCertificateList: map[string]*x509.Certificate{
					constants.SKCoordinatorRootCert: {Raw: []byte("root cert")},
				},
			},
			store: &stubStore{
				setEncryptionKeyErr: someErr,
			},
			recovery: &stubRecovery{},
			core: &fakeCore{
				state: state.Recovery,
			},
			wantErr: true,
		},
		"GetCertificate fails": {
			data: &stubStoreWrapper{
				getCertificateErr: someErr,
			},
			store:    &stubStore{},
			recovery: &stubRecovery{},
			core: &fakeCore{
				state: state.Recovery,
			},
			wantErr: true,
		},
		"GenerateQuote fails": {
			data: &stubStoreWrapper{
				getCertificateList: map[string]*x509.Certificate{
					constants.SKCoordinatorRootCert: {Raw: []byte("root cert")},
				},
			},
			store:    &stubStore{},
			recovery: &stubRecovery{},
			core: &fakeCore{
				state:            state.Recovery,
				generateQuoteErr: someErr,
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			log, err := zap.NewDevelopment()
			require.NoError(err)
			defer func() { _ = log.Sync() }()

			api := &ClientAPI{
				data:     tc.data,
				txHandle: tc.store,
				recovery: tc.recovery,
				core:     tc.core,
				log:      log,
			}

			keysLeft, err := api.Recover([]byte("recoveryKey"))
			if tc.wantErr {
				assert.Error(err)
				return
			}

			require.NoError(err)
			assert.True(tc.core.unlockCalled)
			assert.Equal(tc.recovery.recoverKeysLeft, keysLeft)
			if keysLeft > 0 {
				assert.False(tc.store.loadCalled)
				return
			}
			assert.True(tc.store.loadCalled)
			assert.NotNil(tc.core.quote)
		})
	}
}

func TestSetManifest(t *testing.T) {
	t.Log("WARNING: Missing unit Test for SetManifest")
}

func TestUpdateManifest(t *testing.T) {
	t.Log("WARNING: Missing unit Test for UpdateManifest")
}

func TestVerifyUser(t *testing.T) {
	t.Log("WARNING: Missing unit Test for VerifyUser")
}

func TestWriteSecrets(t *testing.T) {
	t.Log("WARNING: Missing unit Test for WriteSecrets")
}

type fakeCore struct {
	unlockCalled       bool
	state              state.State
	requireStateErr    error
	advanceStateErr    error
	getStateMsg        string
	recoveryErr        error
	quote              []byte
	generateQuoteErr   error
	getStateErr        error
	generatedSecrets   map[string]manifest.Secret
	generateSecretsErr error
}

func (c *fakeCore) Unlock() {
	c.unlockCalled = true
}

func (c *fakeCore) RequireState(states ...state.State) error {
	if c.requireStateErr != nil {
		return c.requireStateErr
	}

	for _, state := range states {
		if state == c.state {
			return nil
		}
	}
	return errors.New("core is not in expected state")
}

func (c *fakeCore) AdvanceState(newState state.State, _ store.Transaction) error {
	if c.advanceStateErr != nil {
		return c.advanceStateErr
	}

	if !(c.state < newState && newState < state.Max) {
		panic("invalid state transition")
	}
	c.state = newState
	return nil
}

func (c *fakeCore) GetState() (state.State, string, error) {
	return c.state, c.getStateMsg, c.getStateErr
}

func (c *fakeCore) GenerateSecrets(newSecrets map[string]manifest.Secret, _ uuid.UUID, rootCert *x509.Certificate, privK *ecdsa.PrivateKey,
) (map[string]manifest.Secret, error) {
	if c.generateSecretsErr != nil || c.generatedSecrets != nil {
		return c.generatedSecrets, c.generateSecretsErr
	}

	secrets := make(map[string]manifest.Secret, len(newSecrets))
	for name, secret := range newSecrets {
		switch secret.Type {
		case manifest.SecretTypeSymmetricKey:
			secret.Public = bytes.Repeat([]byte{0x00}, 32)
			secret.Private = bytes.Repeat([]byte{0x01}, 32)
		case manifest.SecretTypeCertECDSA, manifest.SecretTypeED25519, manifest.SecretTypeCertRSA:
			cert, key, err := crypto.GenerateCert([]string{"localhost"}, name, nil, rootCert, privK)
			if err != nil {
				return nil, err
			}
			secret.Public, err = x509.MarshalPKIXPublicKey(key.Public())
			if err != nil {
				return nil, err
			}
			secret.Private, err = x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return nil, err
			}
			secret.Cert = manifest.Certificate(*cert)
		}
		secrets[name] = secret
	}
	return secrets, nil
}

func (c *fakeCore) GetQuote() []byte {
	return c.quote
}

func (c *fakeCore) GenerateQuote(quoteData []byte) error {
	if c.generateQuoteErr != nil {
		return c.generateQuoteErr
	}

	quote := sha256.Sum256(quoteData)
	c.quote = quote[:]
	return nil
}

type stubStoreWrapper struct {
	getCertificateList      map[string]*x509.Certificate
	getCertificateErr       error
	getPrivateKeyList       map[string]*ecdsa.PrivateKey
	getPrivateKeyErr        error
	rawManifest             []byte
	getRawManifestErr       error
	manifestSignature       []byte
	getManifestSignatureErr error
	wrapper.Wrapper
}

func (s *stubStoreWrapper) GetCertificate(certName string) (*x509.Certificate, error) {
	if s.getCertificateErr != nil {
		return nil, s.getCertificateErr
	}

	cert, ok := s.getCertificateList[certName]
	if !ok {
		return nil, errors.New("certificate not found")
	}

	return cert, nil
}

func (s *stubStoreWrapper) GetPrivateKey(keyName string) (*ecdsa.PrivateKey, error) {
	if s.getPrivateKeyErr != nil {
		return nil, s.getPrivateKeyErr
	}

	key, ok := s.getPrivateKeyList[keyName]
	if !ok {
		return nil, errors.New("private key not found")
	}

	return key, nil
}

func (s *stubStoreWrapper) GetRawManifest() ([]byte, error) {
	return s.rawManifest, s.getRawManifestErr
}

func (s *stubStoreWrapper) GetManifestSignature() ([]byte, error) {
	return s.manifestSignature, s.getManifestSignatureErr
}

type stubStore struct {
	recoveryData        []byte
	encryptionKey       []byte
	setEncryptionKeyErr error
	loadStateRes        []byte
	loadStateErr        error
	loadCalled          bool
}

func (s *stubStore) BeginTransaction() (store.Transaction, error) {
	return nil, nil
}

func (s *stubStore) SetEncryptionKey(key []byte) error {
	if s.setEncryptionKeyErr != nil {
		return s.setEncryptionKeyErr
	}
	s.encryptionKey = key
	return nil
}

func (s *stubStore) SetRecoveryData(recoveryData []byte) {
	s.recoveryData = recoveryData
}

func (s *stubStore) LoadState() ([]byte, error) {
	s.loadCalled = true
	return s.loadStateRes, s.loadStateErr
}

type stubRecovery struct {
	generateEncryptionKeyRes []byte
	generateEncryptionKeyErr error
	generateRecoveryDataRes  map[string][]byte
	generateRecoveryDataErr  error
	recoverKeyRes            []byte
	recoverKeyErr            error
	recoverKeysLeft          int
	getRecoveryDataRes       []byte
	getRecoveryDataErr       error
	setRecoveryDataErr       error
}

func (s *stubRecovery) GenerateEncryptionKey(recoveryKeys map[string]string) ([]byte, error) {
	return s.generateEncryptionKeyRes, s.generateEncryptionKeyErr
}

func (s *stubRecovery) GenerateRecoveryData(recoveryKeys map[string]string) (map[string][]byte, []byte, error) {
	return s.generateRecoveryDataRes, nil, s.generateRecoveryDataErr
}

func (s *stubRecovery) RecoverKey(secret []byte) (int, []byte, error) {
	return s.recoverKeysLeft, s.recoverKeyRes, s.recoverKeyErr
}

func (s *stubRecovery) GetRecoveryData() ([]byte, error) {
	return s.getRecoveryDataRes, s.getRecoveryDataErr
}

func (s *stubRecovery) SetRecoveryData(data []byte) error {
	return s.setRecoveryDataErr
}

func mustEncodeToPem(t *testing.T, cert *x509.Certificate) string {
	t.Helper()

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if pemCert == nil {
		t.Fatal("failed to encode certificate to PEM")
	}
	return string(pemCert)
}
