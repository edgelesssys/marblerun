/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package clientapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/crypto"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/oid"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/store/request"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper/testutil"
	"github.com/edgelesssys/marblerun/coordinator/updatelog"
	"github.com/edgelesssys/marblerun/coordinator/user"
	"github.com/edgelesssys/marblerun/test"
	"github.com/edgelesssys/marblerun/util"
	"github.com/google/uuid"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/zap/zaptest"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestGetCertQuote(t *testing.T) {
	// these are not actually root and intermediate certs
	// but we don't care for this test
	rootCert, intermediateCert := test.MustSetupTestCerts(test.RecoveryPrivateKey)

	prepareDefaultStore := func() store.Store {
		s := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
		require.NoError(t, wrapper.New(s).PutCertificate(constants.SKCoordinatorRootCert, rootCert))
		require.NoError(t, wrapper.New(s).PutCertificate(constants.SKCoordinatorIntermediateCert, intermediateCert))
		return s
	}

	testCases := map[string]struct {
		store     store.Store
		core      *fakeCore
		nonce     []byte
		wantQuote []byte
		wantErr   bool
	}{
		"success state accepting Marbles": {
			store: prepareDefaultStore(),
			core: &fakeCore{
				state: state.AcceptingMarbles,
				quote: []byte("quote"),
			},
			wantQuote: []byte("quote"),
		},
		"success state accepting manifest": {
			store: prepareDefaultStore(),
			core: &fakeCore{
				state: state.AcceptingManifest,
				quote: []byte("quote"),
			},
			wantQuote: []byte("quote"),
		},
		"success state recovery": {
			store: prepareDefaultStore(),
			core: &fakeCore{
				state: state.Recovery,
				quote: []byte("quote"),
			},
			wantQuote: []byte("quote"),
		},
		"unsupported state": {
			store: prepareDefaultStore(),
			core: &fakeCore{
				state: state.Uninitialized,
				quote: []byte("quote"),
			},
			wantErr: true,
		},
		"error getting state": {
			store: prepareDefaultStore(),
			core: &fakeCore{
				requireStateErr: assert.AnError,
				quote:           []byte("quote"),
			},
			wantErr: true,
		},
		"root certificate not set": {
			store: func() store.Store {
				s := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
				require.NoError(t, wrapper.New(s).PutCertificate(constants.SKCoordinatorIntermediateCert, intermediateCert))
				return s
			}(),
			core: &fakeCore{
				state: state.AcceptingMarbles,
				quote: []byte("quote"),
			},
			wantErr: true,
		},
		"intermediate certificate not set": {
			store: func() store.Store {
				s := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
				require.NoError(t, wrapper.New(s).PutCertificate(constants.SKCoordinatorRootCert, rootCert))
				return s
			}(),
			core: &fakeCore{
				state: state.AcceptingMarbles,
				quote: []byte("quote"),
			},
			wantErr: true,
		},
		"get quote with nonce": {
			store: prepareDefaultStore(),
			core: &fakeCore{
				state: state.AcceptingMarbles,
				quote: []byte("quote"),
			},
			nonce:     []byte("nonce"),
			wantQuote: []byte("nonce" + "quote"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			log := zaptest.NewLogger(t)

			api := &ClientAPI{
				core:     tc.core,
				txHandle: tc.store,
				log:      log,
			}

			var intermediateCert, rootCert *x509.Certificate
			if !tc.wantErr {
				intermediateCert = testutil.GetCertificate(t, tc.store, constants.SKCoordinatorIntermediateCert)
				rootCert = testutil.GetCertificate(t, tc.store, constants.SKCoordinatorRootCert)
			}

			cert, quote, err := api.GetCertQuote(context.Background(), tc.nonce)
			if tc.wantErr {
				assert.Error(err)
				return
			}

			require.NoError(err)
			assert.Equal(tc.wantQuote, quote)
			assert.Equal(mustEncodeToPem(t, intermediateCert)+mustEncodeToPem(t, rootCert), cert)
		})
	}
}

func TestGetManifestSignature(t *testing.T) {
	testCases := map[string]struct {
		store   store.Store
		wantErr bool
	}{
		"success": {
			store: func() store.Store {
				s := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
				require.NoError(t, s.Put(request.Manifest, []byte("manifest")))
				require.NoError(t, s.Put(request.ManifestSignature, []byte("signature")))
				return s
			}(),
		},
		"GetRawManifest fails": {
			store: func() store.Store {
				s := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
				require.NoError(t, s.Put(request.ManifestSignature, []byte("signature")))
				return s
			}(),
			wantErr: true,
		},
		"GetManifestSignature fails": {
			store: func() store.Store {
				s := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
				require.NoError(t, s.Put(request.Manifest, []byte("manifest")))
				return s
			}(),
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			log := zaptest.NewLogger(t)

			api := &ClientAPI{
				txHandle: tc.store,
				log:      log,
			}

			var rawManifest, manifestSignature []byte
			if !tc.wantErr {
				rawManifest = testutil.GetRawManifest(t, tc.store)
				manifestSignature = testutil.GetManifestSignature(t, tc.store)
			}

			signature, manifest, err := api.GetManifestSignature(context.Background())
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Equal(rawManifest, manifest)
			assert.Equal(manifestSignature, signature)
		})
	}
}

func TestGetSecrets(t *testing.T) {
	newUserWithPermissions := func(name string, secretNames ...string) *user.User {
		u := user.NewUser(name, nil)
		u.Assign(user.NewPermission(user.PermissionReadSecret, secretNames))
		return u
	}

	testCases := map[string]struct {
		store   store.Store
		core    *fakeCore
		request []string
		user    *user.User
		wantErr bool
	}{
		"success": {
			store: func() store.Store {
				s := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
				require.NoError(t, wrapper.New(s).PutSecret("secret1", manifest.Secret{
					Type:    manifest.SecretTypePlain,
					Private: []byte("secret"),
				}))
				require.NoError(t, wrapper.New(s).PutSecret("secret2", manifest.Secret{
					Type:    manifest.SecretTypePlain,
					Private: []byte("secret"),
				}))
				return s
			}(),
			core: &fakeCore{state: state.AcceptingMarbles},
			request: []string{
				"secret1",
				"secret2",
			},
			user: newUserWithPermissions("test", "secret1", "secret2"),
		},
		"wrong state": {
			store: func() store.Store {
				s := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
				require.NoError(t, wrapper.New(s).PutSecret("secret1", manifest.Secret{
					Type:    manifest.SecretTypePlain,
					Private: []byte("secret"),
				}))
				require.NoError(t, wrapper.New(s).PutSecret("secret2", manifest.Secret{
					Type:    manifest.SecretTypePlain,
					Private: []byte("secret"),
				}))
				return s
			}(),
			core: &fakeCore{state: state.AcceptingManifest},
			request: []string{
				"secret1",
				"secret2",
			},
			user:    newUserWithPermissions("test", "secret1", "secret2"),
			wantErr: true,
		},
		"user is missing permissions": {
			store: func() store.Store {
				s := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
				require.NoError(t, wrapper.New(s).PutSecret("secret1", manifest.Secret{
					Type:    manifest.SecretTypePlain,
					Private: []byte("secret"),
				}))
				require.NoError(t, wrapper.New(s).PutSecret("secret2", manifest.Secret{
					Type:    manifest.SecretTypePlain,
					Private: []byte("secret"),
				}))
				return s
			}(),
			core: &fakeCore{state: state.AcceptingMarbles},
			request: []string{
				"secret1",
				"secret2",
			},
			user:    newUserWithPermissions("test", "secret2"), // only permission for secret2
			wantErr: true,
		},
		"secret does not exist": {
			store: func() store.Store {
				s := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
				require.NoError(t, wrapper.New(s).PutSecret("secret1", manifest.Secret{
					Type:    manifest.SecretTypePlain,
					Private: []byte("secret"),
				}))
				return s
			}(),
			core: &fakeCore{state: state.AcceptingMarbles},
			request: []string{
				"secret1",
				"secret2",
			},
			user:    newUserWithPermissions("test", "secret1", "secret2"),
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			log := zaptest.NewLogger(t)

			api := &ClientAPI{
				txHandle: tc.store,
				core:     tc.core,
				log:      log,
			}

			storedSecrets := testutil.GetSecretMap(t, tc.store)

			secrets, err := api.GetSecrets(context.Background(), tc.request, tc.user)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)
			for name, secret := range secrets {
				assert.Equal(storedSecrets[name], secret)
			}
		})
	}
}

func TestGetStatus(t *testing.T) {
	testCases := map[string]struct {
		core    *fakeCore
		wantErr bool
	}{
		"success": {
			core: &fakeCore{state: state.AcceptingManifest},
		},
		"error": {
			core: &fakeCore{
				state:       state.AcceptingManifest,
				getStateErr: errors.New("failed"),
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			log := zaptest.NewLogger(t)

			api := &ClientAPI{
				core: tc.core,
				log:  log,
			}

			status, _, err := api.GetStatus(context.Background())
			if tc.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tc.core.state, status)
		})
	}
}

func TestGetUpdateLog(t *testing.T) {
	t.Log("WARNING: Missing unit Test for GetUpdateLog")
}

func TestRecover(t *testing.T) {
	_, rootCert := test.MustSetupTestCerts(test.RecoveryPrivateKey)
	defaultStore := func() store.Store {
		s := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
		s.SetEncryptionKey([]byte("key"), seal.ModeProductKey) // set encryption key to set seal mode
		wr := wrapper.New(s)
		require.NoError(t, wr.PutCertificate(constants.SKCoordinatorRootCert, rootCert))
		require.NoError(t, wr.PutRawManifest([]byte(test.ManifestJSONWithRecoveryKey)))
		return s
	}
	signData := func(d []byte, k *rsa.PrivateKey) []byte {
		sig, err := util.SignPKCS1v15(k, d)
		require.NoError(t, err)
		return sig
	}

	testCases := map[string]struct {
		store          *fakeStore
		recovery       *stubRecovery
		core           *fakeCore
		recoveryKey    []byte
		recoveryKeySig []byte
		wantErr        bool
	}{
		"success": {
			store: &fakeStore{
				store: defaultStore(),
			},
			recovery: &stubRecovery{},
			core: &fakeCore{
				state: state.Recovery,
			},
			recoveryKey:    bytes.Repeat([]byte{0x01}, 16),
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKey),
		},
		"more than one key required": {
			store: &fakeStore{
				store: defaultStore(),
			},
			recovery: &stubRecovery{
				recoverKeysLeft: 1,
			},
			core: &fakeCore{
				state: state.Recovery,
			},
			recoveryKey:    bytes.Repeat([]byte{0x01}, 16),
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKey),
		},
		"SetRecoveryData fails does not result in error": {
			store: &fakeStore{
				store: defaultStore(),
			},
			recovery: &stubRecovery{
				setRecoveryDataErr: assert.AnError,
			},
			core: &fakeCore{
				state: state.Recovery,
			},
			recoveryKey:    bytes.Repeat([]byte{0x01}, 16),
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKey),
		},
		"Coordinator not in recovery state": {
			store: &fakeStore{
				store: defaultStore(),
			},
			recovery: &stubRecovery{},
			core: &fakeCore{
				state: state.AcceptingManifest,
			},
			recoveryKey:    bytes.Repeat([]byte{0x01}, 16),
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKey),
			wantErr:        true,
		},
		"RecoverKey fails": {
			store: &fakeStore{
				store: defaultStore(),
			},
			recovery: &stubRecovery{
				recoverKeyErr: assert.AnError,
			},
			core: &fakeCore{
				state: state.Recovery,
			},
			recoveryKey:    bytes.Repeat([]byte{0x01}, 16),
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKey),
			wantErr:        true,
		},
		"LoadState fails": {
			store: &fakeStore{
				store:        defaultStore(),
				loadStateErr: assert.AnError,
			},
			recovery: &stubRecovery{},
			core: &fakeCore{
				state: state.Recovery,
			},
			recoveryKey:    bytes.Repeat([]byte{0x01}, 16),
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKey),
			wantErr:        true,
		},
		"SealEncryptionKey fails does return an error": {
			store: &fakeStore{
				store:                defaultStore(),
				sealEncryptionKeyErr: assert.AnError,
			},
			recovery: &stubRecovery{},
			core: &fakeCore{
				state: state.Recovery,
			},
			recoveryKey:    bytes.Repeat([]byte{0x01}, 16),
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKey),
		},
		"GetCertificate fails": {
			store: &fakeStore{
				store: func() store.Store {
					s := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
					s.SetEncryptionKey([]byte("key"), seal.ModeProductKey) // set encryption key to set seal mode
					wr := wrapper.New(s)
					require.NoError(t, wr.PutRawManifest([]byte(test.ManifestJSONWithRecoveryKey)))
					return s
				}(),
			},
			recovery: &stubRecovery{},
			core: &fakeCore{
				state: state.Recovery,
			},
			recoveryKey:    bytes.Repeat([]byte{0x01}, 16),
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKey),
			wantErr:        true,
		},
		"GenerateQuote fails": {
			store: &fakeStore{
				store: defaultStore(),
			},
			recovery: &stubRecovery{},
			core: &fakeCore{
				state:            state.Recovery,
				generateQuoteErr: assert.AnError,
			},
			recoveryKey:    bytes.Repeat([]byte{0x01}, 16),
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKey),
			wantErr:        true,
		},
		"invalid recovery key signature": {
			store: &fakeStore{
				store: defaultStore(),
			},
			recovery: &stubRecovery{},
			core: &fakeCore{
				state: state.Recovery,
			},
			recoveryKey:    bytes.Repeat([]byte{0x01}, 16),
			recoveryKeySig: signData(bytes.Repeat([]byte{0xFF}, 16), test.RecoveryPrivateKey),
			wantErr:        true,
		},
		"manifest defines multiple recovery keys": {
			store: &fakeStore{
				store: func() store.Store {
					s := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
					s.SetEncryptionKey([]byte("key"), seal.ModeProductKey) // set encryption key to set seal mode
					wr := wrapper.New(s)
					require.NoError(t, wr.PutCertificate(constants.SKCoordinatorRootCert, rootCert))
					recoveryKey2Str := fmt.Sprintf("\"testRecKey2\": \"%s\",\"testRecKey1\":", strings.ReplaceAll(string(test.RecoveryPublicKey), "\n", "\\n"))
					mnf := strings.Replace(test.ManifestJSONWithRecoveryKey, `"testRecKey1":`, recoveryKey2Str, 1)
					require.NoError(t, wr.PutRawManifest([]byte(mnf)))
					return s
				}(),
			},
			recovery: &stubRecovery{},
			core: &fakeCore{
				state: state.Recovery,
			},
			recoveryKey:    bytes.Repeat([]byte{0x01}, 16),
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKey),
			wantErr:        true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			log := zaptest.NewLogger(t)

			api := &ClientAPI{
				txHandle: tc.store,
				recovery: tc.recovery,
				core:     tc.core,
				log:      log,
			}

			keysLeft, err := api.Recover(context.Background(), tc.recoveryKey, tc.recoveryKeySig)
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
			assert.True(tc.store.setRecoveryDataCalled)
			assert.True(tc.store.loadCalled)
			assert.NotNil(tc.core.quote)
		})
	}
}

func TestSetManifest(t *testing.T) {
	testCases := map[string]struct {
		store        *fakeStoreTransaction
		core         *fakeCore
		manifest     []byte
		wantErr      bool
		wantSealMode seal.Mode
	}{
		"success": {
			store: &fakeStoreTransaction{
				state: make(map[string][]byte),
			},
			core: &fakeCore{
				state: state.AcceptingManifest,
			},
			manifest:     []byte(test.ManifestJSON),
			wantSealMode: seal.ModeProductKey,
		},
		"seal mode set to product key": {
			store: &fakeStoreTransaction{
				state: make(map[string][]byte),
			},
			core: &fakeCore{
				state: state.AcceptingManifest,
			},
			manifest: func() []byte {
				var mnf manifest.Manifest
				require.NoError(t, json.Unmarshal([]byte(test.ManifestJSON), &mnf))
				mnf.Config.SealMode = "ProductKey"
				mnfBytes, err := json.Marshal(mnf)
				require.NoError(t, err)
				return mnfBytes
			}(),
			wantSealMode: seal.ModeProductKey,
		},
		"seal mode set to unique key": {
			store: &fakeStoreTransaction{
				state: make(map[string][]byte),
			},
			core: &fakeCore{
				state: state.AcceptingManifest,
			},
			manifest: func() []byte {
				var mnf manifest.Manifest
				require.NoError(t, json.Unmarshal([]byte(test.ManifestJSON), &mnf))
				mnf.Config.SealMode = "UniqueKey"
				mnfBytes, err := json.Marshal(mnf)
				require.NoError(t, err)
				return mnfBytes
			}(),
			wantSealMode: seal.ModeUniqueKey,
		},
		"seal mode set to disabled": {
			store: &fakeStoreTransaction{
				state: make(map[string][]byte),
			},
			core: &fakeCore{
				state: state.AcceptingManifest,
			},
			manifest: func() []byte {
				var mnf manifest.Manifest
				require.NoError(t, json.Unmarshal([]byte(test.ManifestJSON), &mnf))
				mnf.Config.SealMode = "Disabled"
				mnfBytes, err := json.Marshal(mnf)
				require.NoError(t, err)
				return mnfBytes
			}(),
			wantSealMode: seal.ModeDisabled,
		},
		"invalid seal mode": {
			store: &fakeStoreTransaction{
				state: make(map[string][]byte),
			},
			core: &fakeCore{
				state: state.AcceptingManifest,
			},
			manifest: func() []byte {
				var mnf manifest.Manifest
				require.NoError(t, json.Unmarshal([]byte(test.ManifestJSON), &mnf))
				mnf.Config.SealMode = "foo"
				mnfBytes, err := json.Marshal(mnf)
				require.NoError(t, err)
				return mnfBytes
			}(),
			wantErr: true,
		},
		"wrong state": {
			store: &fakeStoreTransaction{
				state: make(map[string][]byte),
			},
			core: &fakeCore{
				state: state.AcceptingMarbles,
			},
			manifest: []byte(test.ManifestJSON),
			wantErr:  true,
		},
		"transaction cannot be committed": {
			store: &fakeStoreTransaction{
				state:     make(map[string][]byte),
				commitErr: assert.AnError,
			},
			core: &fakeCore{
				state: state.AcceptingManifest,
			},
			manifest: []byte(test.ManifestJSON),
			wantErr:  true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			log := zaptest.NewLogger(t)

			updateLog, err := updatelog.New()
			require.NoError(err)

			api := &ClientAPI{
				txHandle:  tc.store,
				core:      tc.core,
				recovery:  &stubRecovery{},
				updateLog: updateLog,
				log:       log,
			}

			wrapper := wrapper.New(tc.store)
			rootCert, rootKey, err := crypto.GenerateCert([]string{"localhost"}, "MarbleRun Unit Test Root", nil, nil, nil)
			require.NoError(err)
			intermediateCert, intermediateKey, err := crypto.GenerateCert([]string{"localhost"}, "MarbleRun Unit Test Intermediate", nil, rootCert, rootKey)
			require.NoError(err)
			marbleCert, _, err := crypto.GenerateCert([]string{"localhost"}, "MarbleRun Unit Test Marble", intermediateKey, nil, nil)
			require.NoError(err)

			require.NoError(wrapper.PutCertificate(constants.SKCoordinatorRootCert, rootCert))
			require.NoError(wrapper.PutCertificate(constants.SKCoordinatorIntermediateCert, intermediateCert))
			require.NoError(wrapper.PutCertificate(constants.SKMarbleRootCert, marbleCert))
			require.NoError(wrapper.PutPrivateKey(constants.SKCoordinatorRootKey, rootKey))
			require.NoError(wrapper.PutPrivateKey(constants.SKCoordinatorIntermediateKey, intermediateKey))

			_, err = api.SetManifest(context.Background(), tc.manifest)
			if tc.wantErr {
				assert.Error(err)
				if tc.store.beginTransactionCalled {
					assert.True(tc.store.rollbackCalled)
				}
				return
			}

			require.NoError(err)
			assert.True(tc.core.unlockCalled)
			assert.True(tc.store.commitCalled)
			assert.Equal(tc.wantSealMode, tc.store.sealMode)
		})
	}
}

func TestSetMonotonicCounter(t *testing.T) {
	const defaultType = "type"
	defaultUUID := uuid.UUID{2, 3, 4}
	const defaultName = "name"
	defaultID := encodeMonotonicCounterID(defaultType, defaultUUID, defaultName)
	defaultKey := "monotonicCounter:" + defaultID

	testCases := map[string]struct {
		coreState      state.State
		store          fakeStoreTransaction
		marbleType     string
		marbleUUID     uuid.UUID
		name           string
		value          uint64
		wantValue      uint64
		wantStoreValue []byte
		wantErr        bool
	}{
		"new value is smaller": {
			coreState: state.AcceptingMarbles,
			store: fakeStoreTransaction{
				state: map[string][]byte{defaultKey: {3, 0, 0, 0, 0, 0, 0, 0}},
			},
			marbleType:     defaultType,
			marbleUUID:     defaultUUID,
			name:           defaultName,
			value:          2,
			wantValue:      3,
			wantStoreValue: []byte{3, 0, 0, 0, 0, 0, 0, 0},
		},
		"new value is equal": {
			coreState: state.AcceptingMarbles,
			store: fakeStoreTransaction{
				state: map[string][]byte{defaultKey: {3, 0, 0, 0, 0, 0, 0, 0}},
			},
			marbleType:     defaultType,
			marbleUUID:     defaultUUID,
			name:           defaultName,
			value:          3,
			wantValue:      3,
			wantStoreValue: []byte{3, 0, 0, 0, 0, 0, 0, 0},
		},
		"new value is greater": {
			coreState: state.AcceptingMarbles,
			store: fakeStoreTransaction{
				state: map[string][]byte{defaultKey: {3, 0, 0, 0, 0, 0, 0, 0}},
			},
			marbleType:     defaultType,
			marbleUUID:     defaultUUID,
			name:           defaultName,
			value:          4,
			wantValue:      3,
			wantStoreValue: []byte{4, 0, 0, 0, 0, 0, 0, 0},
		},
		"wrong core state": {
			coreState: state.AcceptingManifest,
			store: fakeStoreTransaction{
				state: map[string][]byte{defaultKey: {3, 0, 0, 0, 0, 0, 0, 0}},
			},
			marbleType: defaultType,
			marbleUUID: defaultUUID,
			name:       defaultName,
			value:      4,
			wantErr:    true,
		},
		"counter not set yet": {
			coreState: state.AcceptingMarbles,
			store: fakeStoreTransaction{
				state:  map[string][]byte{},
				getErr: store.ErrValueUnset,
			},
			marbleType:     defaultType,
			marbleUUID:     defaultUUID,
			name:           defaultName,
			value:          4,
			wantValue:      0,
			wantStoreValue: []byte{4, 0, 0, 0, 0, 0, 0, 0},
		},
		"store error": {
			coreState: state.AcceptingMarbles,
			store: fakeStoreTransaction{
				state:  map[string][]byte{defaultKey: {3, 0, 0, 0, 0, 0, 0, 0}},
				getErr: assert.AnError,
			},
			marbleType: defaultType,
			marbleUUID: defaultUUID,
			name:       defaultName,
			value:      4,
			wantErr:    true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			api := ClientAPI{
				txHandle: &tc.store,
				core:     &fakeCore{state: tc.coreState},
				log:      zaptest.NewLogger(t),
			}

			gotValue, err := api.SetMonotonicCounter(context.Background(), tc.marbleType, tc.marbleUUID, tc.name, tc.value)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)

			assert.Equal(tc.wantValue, gotValue)
			assert.Equal(tc.wantStoreValue, tc.store.state[defaultKey])
		})
	}
}

func TestSignQuote(t *testing.T) {
	testCases := map[string]struct {
		store              *fakeStoreTransaction
		quote              []byte
		verifyFunc         func([]byte) (attestation.Report, error)
		wantErr            bool
		wantQuoteVerifyErr bool
	}{
		"success": {
			quote: []byte("quote"),
			store: &fakeStoreTransaction{},
			verifyFunc: func([]byte) (attestation.Report, error) {
				return attestation.Report{}, nil
			},
		},
		"success with non standard TCB status": {
			quote: []byte("quote"),
			store: &fakeStoreTransaction{},
			verifyFunc: func([]byte) (attestation.Report, error) {
				return attestation.Report{TCBStatus: tcbstatus.OutOfDate}, attestation.ErrTCBLevelInvalid
			},
		},
		"success with raw SGX quote": {
			quote: func() []byte {
				quote := make([]byte, 64)
				binary.LittleEndian.PutUint16(quote[0:2], 3)
				binary.LittleEndian.PutUint16(quote[2:4], 3)
				binary.LittleEndian.PutUint32(quote[4:8], 0)
				binary.LittleEndian.PutUint16(quote[8:10], 42)
				binary.LittleEndian.PutUint16(quote[10:12], 42)
				return quote
			}(),
			store: &fakeStoreTransaction{},
			verifyFunc: func([]byte) (attestation.Report, error) {
				return attestation.Report{}, nil
			},
		},
		"quote verification fails": {
			quote: []byte("quote"),
			store: &fakeStoreTransaction{},
			verifyFunc: func([]byte) (attestation.Report, error) {
				return attestation.Report{}, assert.AnError
			},
			wantErr:            true,
			wantQuoteVerifyErr: true,
		},
		"retrieving root key fails": {
			quote: []byte("quote"),
			store: &fakeStoreTransaction{
				getErr: assert.AnError,
			},
			verifyFunc: func([]byte) (attestation.Report, error) {
				return attestation.Report{}, nil
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			log := zaptest.NewLogger(t)
			tc.store.state = make(map[string][]byte)

			api := &ClientAPI{
				txHandle: tc.store,
				core:     &fakeCore{},
				log:      log,
			}

			wrapper := wrapper.New(tc.store)
			_, rootKey, err := crypto.GenerateCert([]string{"localhost"}, "MarbleRun Unit Test Root", nil, nil, nil)
			require.NoError(err)
			require.NoError(wrapper.PutPrivateKey(constants.SKCoordinatorRootKey, rootKey))

			signature, tcbStatus, err := api.verifyAndSignQuote(context.Background(), tc.quote, tc.verifyFunc)
			if tc.wantErr {
				assert.Error(err)

				if tc.wantQuoteVerifyErr {
					var verifyErr *QuoteVerifyError
					assert.ErrorAs(err, &verifyErr)
				}
				return
			}
			assert.NoError(err)
			hash := sha256.Sum256([]byte(base64.StdEncoding.EncodeToString(tc.quote) + tcbStatus))
			assert.True(ecdsa.VerifyASN1(&rootKey.PublicKey, hash[:], signature))
		})
	}
}

func TestFeatureEnabled(t *testing.T) {
	testCases := map[string]struct {
		store       *fakeStoreTransaction
		feature     string
		wantEnabled bool
	}{
		"sign-quote feature enabled": {
			store: &fakeStoreTransaction{
				state: map[string][]byte{
					request.Manifest: []byte(test.ManifestJSON),
				},
			},
			feature:     manifest.FeatureSignQuoteEndpoint,
			wantEnabled: true,
		},
		"sign-quote feature disabled": {
			store: &fakeStoreTransaction{
				state: map[string][]byte{
					request.Manifest: func() []byte {
						var mnf manifest.Manifest
						require.NoError(t, json.Unmarshal([]byte(test.ManifestJSON), &mnf))
						mnf.Config.FeatureGates = []string{}
						mnfBytes, err := json.Marshal(mnf)
						require.NoError(t, err)
						return mnfBytes
					}(),
				},
			},
			feature:     manifest.FeatureSignQuoteEndpoint,
			wantEnabled: false,
		},
		"unknown feature": {
			store: &fakeStoreTransaction{
				state: map[string][]byte{
					request.Manifest: []byte(test.ManifestJSON),
				},
			},
			feature:     "unknown",
			wantEnabled: false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			log := zaptest.NewLogger(t)

			api := &ClientAPI{
				txHandle: tc.store,
				core:     &fakeCore{},
				log:      log,
			}

			assert.Equal(tc.wantEnabled, api.FeatureEnabled(context.Background(), tc.feature))
		})
	}
}

func TestUpdateManifest(t *testing.T) {
	t.Log("WARNING: Missing unit Test for UpdateManifest")
}

func TestVerifyMarble(t *testing.T) {
	marbleRootCert, marbleRootKey, err := crypto.GenerateCert(nil, "MarbleRun Unit Test Marble", nil, nil, nil)
	require.NoError(t, err)
	otherRootCert, otherRootKey, err := crypto.GenerateCert(nil, "MarbleRun Unit Test Marble", nil, nil, nil)
	require.NoError(t, err)

	createCert := func(template *x509.Certificate, rootCert *x509.Certificate, rootKey *ecdsa.PrivateKey) *x509.Certificate {
		marblePubKey := &rsa.PublicKey{N: big.NewInt(1), E: 1}
		certRaw, err := x509.CreateCertificate(rand.Reader, template, rootCert, marblePubKey, rootKey)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(certRaw)
		require.NoError(t, err)
		return cert
	}

	testCases := map[string]struct {
		coreState   state.State
		clientCerts []*x509.Certificate
		wantType    string
		wantUUID    uuid.UUID
		wantErr     bool
	}{
		"success": {
			coreState: state.AcceptingMarbles,
			clientCerts: []*x509.Certificate{
				createCert(&x509.Certificate{
					SerialNumber:    &big.Int{},
					Subject:         pkix.Name{CommonName: "02030400-0000-0000-0000-000000000000"},
					NotAfter:        time.Now().Add(time.Hour),
					ExtraExtensions: []pkix.Extension{{Id: oid.MarbleType, Value: []byte("type")}},
				}, marbleRootCert, marbleRootKey),
			},
			wantType: "type",
			wantUUID: uuid.UUID{2, 3, 4},
		},
		"wrong core state": {
			coreState: state.AcceptingManifest,
			clientCerts: []*x509.Certificate{
				createCert(&x509.Certificate{
					SerialNumber:    &big.Int{},
					Subject:         pkix.Name{CommonName: "02030400-0000-0000-0000-000000000000"},
					NotAfter:        time.Now().Add(time.Hour),
					ExtraExtensions: []pkix.Extension{{Id: oid.MarbleType, Value: []byte("type")}},
				}, marbleRootCert, marbleRootKey),
			},
			wantErr: true,
		},
		"invalid signer": {
			coreState: state.AcceptingMarbles,
			clientCerts: []*x509.Certificate{
				createCert(&x509.Certificate{
					SerialNumber:    &big.Int{},
					Subject:         pkix.Name{CommonName: "02030400-0000-0000-0000-000000000000"},
					NotAfter:        time.Now().Add(time.Hour),
					ExtraExtensions: []pkix.Extension{{Id: oid.MarbleType, Value: []byte("type")}},
				}, otherRootCert, otherRootKey),
			},
			wantErr: true,
		},
		"invalid CN": {
			coreState: state.AcceptingMarbles,
			clientCerts: []*x509.Certificate{
				createCert(&x509.Certificate{
					SerialNumber:    &big.Int{},
					Subject:         pkix.Name{CommonName: "foo"},
					NotAfter:        time.Now().Add(time.Hour),
					ExtraExtensions: []pkix.Extension{{Id: oid.MarbleType, Value: []byte("type")}},
				}, marbleRootCert, marbleRootKey),
			},
			wantErr: true,
		},
		"missing Marble type": {
			coreState: state.AcceptingMarbles,
			clientCerts: []*x509.Certificate{
				createCert(&x509.Certificate{
					SerialNumber: &big.Int{},
					Subject:      pkix.Name{CommonName: "02030400-0000-0000-0000-000000000000"},
					NotAfter:     time.Now().Add(time.Hour),
				}, marbleRootCert, marbleRootKey),
			},
			wantErr: true,
		},
		"multiple certificates": {
			coreState: state.AcceptingMarbles,
			clientCerts: []*x509.Certificate{
				createCert(&x509.Certificate{
					SerialNumber:    &big.Int{},
					Subject:         pkix.Name{CommonName: "02030500-0000-0000-0000-000000000000"},
					NotAfter:        time.Now().Add(time.Hour),
					ExtraExtensions: []pkix.Extension{{Id: oid.MarbleType, Value: []byte("other")}},
				}, otherRootCert, otherRootKey),
				createCert(&x509.Certificate{
					SerialNumber:    &big.Int{},
					Subject:         pkix.Name{CommonName: "02030400-0000-0000-0000-000000000000"},
					NotAfter:        time.Now().Add(time.Hour),
					ExtraExtensions: []pkix.Extension{{Id: oid.MarbleType, Value: []byte("type")}},
				}, marbleRootCert, marbleRootKey),
			},
			wantType: "type",
			wantUUID: uuid.UUID{2, 3, 4},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			// prepare store and API
			store := &fakeStoreTransaction{state: map[string][]byte{}}
			require.NoError(wrapper.New(store).PutCertificate(constants.SKMarbleRootCert, marbleRootCert))
			api := ClientAPI{
				txHandle: store,
				core:     &fakeCore{state: tc.coreState},
				log:      zaptest.NewLogger(t),
			}

			marbleType, marbleUUID, err := api.VerifyMarble(context.Background(), tc.clientCerts)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)

			assert.Equal(tc.wantType, marbleType)
			assert.Equal(tc.wantUUID, marbleUUID)
		})
	}
}

func TestVerifyUser(t *testing.T) {
	t.Log("WARNING: Missing unit Test for VerifyUser")
}

func TestWriteSecrets(t *testing.T) {
	t.Log("WARNING: Missing unit Test for WriteSecrets")
}

type fakeCore struct {
	unlockCalled    bool
	state           state.State
	requireStateErr error
	advanceStateErr error
	getStateMsg     string
	// recoveryErr        error
	quote              []byte
	generateQuoteErr   error
	getStateErr        error
	generatedSecrets   map[string]manifest.Secret
	generateSecretsErr error
}

func (c *fakeCore) Unlock() {
	c.unlockCalled = true
}

func (c *fakeCore) RequireState(_ context.Context, states ...state.State) error {
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

func (c *fakeCore) AdvanceState(newState state.State, _ interface {
	PutState(state.State) error
	GetState() (state.State, error)
},
) error {
	if c.advanceStateErr != nil {
		return c.advanceStateErr
	}

	if !(c.state < newState && newState < state.Max) {
		panic("invalid state transition")
	}
	c.state = newState
	return nil
}

func (c *fakeCore) GetState(_ context.Context) (state.State, string, error) {
	return c.state, c.getStateMsg, c.getStateErr
}

func (c *fakeCore) GenerateSecrets(
	newSecrets map[string]manifest.Secret, _ uuid.UUID, _ string, rootCert *x509.Certificate, privK *ecdsa.PrivateKey, _ *ecdsa.PrivateKey,
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
		case manifest.SecretTypeCertECDSA, manifest.SecretTypeCertED25519, manifest.SecretTypeCertRSA:
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

func (c *fakeCore) GetQuote(reportData []byte) ([]byte, error) {
	if reportData != nil {
		return append([]byte("nonce"), c.quote...), nil
	}
	return c.quote, nil
}

func (c *fakeCore) GenerateQuote(quoteData []byte) error {
	if c.generateQuoteErr != nil {
		return c.generateQuoteErr
	}

	quote := sha256.Sum256(quoteData)
	c.quote = quote[:]
	return nil
}

type fakeStore struct {
	store                 store.Store
	beginTransactionErr   error
	setRecoveryDataCalled bool
	recoveryData          []byte
	encryptionKey         []byte
	loadStateRes          []byte
	loadStateErr          error
	loadCalled            bool
	sealEncryptionKeyErr  error
}

func (s *fakeStore) BeginTransaction(ctx context.Context) (store.Transaction, error) {
	if s.beginTransactionErr != nil {
		return nil, s.beginTransactionErr
	}
	return s.store.BeginTransaction(ctx)
}

func (s *fakeStore) SetEncryptionKey(key []byte, _ seal.Mode) {
	s.encryptionKey = key
}

func (s *fakeStore) SealEncryptionKey(_ []byte) error {
	return s.sealEncryptionKeyErr
}

func (s *fakeStore) SetRecoveryData(recoveryData []byte) {
	s.setRecoveryDataCalled = true
	s.recoveryData = recoveryData
}

func (s *fakeStore) LoadState() ([]byte, []byte, error) {
	s.loadCalled = true
	return s.loadStateRes, nil, s.loadStateErr
}

func (s *fakeStore) BeginReadTransaction(ctx context.Context, recoveryKey []byte) (store.ReadTransaction, error) {
	return s.store.BeginReadTransaction(ctx, recoveryKey)
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

func (s *stubRecovery) GenerateEncryptionKey(_ map[string]string) ([]byte, error) {
	return s.generateEncryptionKeyRes, s.generateEncryptionKeyErr
}

func (s *stubRecovery) GenerateRecoveryData(_ map[string]string) (map[string][]byte, []byte, error) {
	return s.generateRecoveryDataRes, nil, s.generateRecoveryDataErr
}

func (s *stubRecovery) RecoverKey(_ []byte) (int, []byte, error) {
	return s.recoverKeysLeft, s.recoverKeyRes, s.recoverKeyErr
}

func (s *stubRecovery) GetRecoveryData() ([]byte, error) {
	return s.getRecoveryDataRes, s.getRecoveryDataErr
}

func (s *stubRecovery) SetRecoveryData(_ []byte) error {
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

type fakeStoreTransaction struct {
	beginTransactionCalled bool
	beginTransactionErr    error
	setEncryptionKeyCalled bool
	sealMode               seal.Mode
	loadStateCalled        bool
	loadStateErr           error
	setRecoveryDataCalled  bool
	sealEncryptionKeyErr   error

	state          map[string][]byte
	getErr         error
	putErr         error
	deleteErr      error
	iteratorErr    error
	commitErr      error
	commitCalled   bool
	rollbackCalled bool
}

func (s *fakeStoreTransaction) BeginTransaction(_ context.Context) (store.Transaction, error) {
	s.beginTransactionCalled = true
	return s, s.beginTransactionErr
}

func (s *fakeStoreTransaction) SetEncryptionKey(_ []byte, mode seal.Mode) {
	s.setEncryptionKeyCalled = true
	s.sealMode = mode
}

func (s *fakeStoreTransaction) SealEncryptionKey(_ []byte) error {
	return s.sealEncryptionKeyErr
}

func (s *fakeStoreTransaction) SetRecoveryData(_ []byte) {
	s.setRecoveryDataCalled = true
}

func (s *fakeStoreTransaction) LoadState() ([]byte, []byte, error) {
	s.loadStateCalled = true
	return nil, nil, s.loadStateErr
}

func (s *fakeStoreTransaction) BeginReadTransaction(_ context.Context, _ []byte) (store.ReadTransaction, error) {
	return s, nil
}

func (s *fakeStoreTransaction) Get(key string) ([]byte, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.state[key], nil
}

func (s *fakeStoreTransaction) Put(key string, data []byte) error {
	if s.putErr != nil {
		return s.putErr
	}
	s.state[key] = data
	return nil
}

func (s *fakeStoreTransaction) Delete(key string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	delete(s.state, key)
	return nil
}

func (s *fakeStoreTransaction) Iterator(_ string) (store.Iterator, error) {
	if s.iteratorErr != nil {
		return nil, s.iteratorErr
	}
	return nil, nil
}

func (s *fakeStoreTransaction) Commit(_ context.Context) error {
	s.commitCalled = true
	return s.commitErr
}

func (s *fakeStoreTransaction) Rollback() {
	s.rollbackCalled = true
}
