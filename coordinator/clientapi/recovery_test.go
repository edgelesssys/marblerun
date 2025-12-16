/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package clientapi

import (
	"bytes"
	"context"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/distributor"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper"
	test "github.com/edgelesssys/marblerun/test"
	"github.com/edgelesssys/marblerun/util"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestRecoveryPublicKey(t *testing.T) {
	testCases := map[string]struct {
		state    state.State
		recovery func(*zap.Logger) recovery.Recovery
		wantErr  bool
	}{
		"success": {
			state:    state.Recovery,
			recovery: func(z *zap.Logger) recovery.Recovery { return recovery.New(nil, z) },
		},
		"coordinator not in recovery state": {
			state:    state.AcceptingManifest,
			recovery: func(z *zap.Logger) recovery.Recovery { return recovery.New(nil, z) },
			wantErr:  true,
		},
		"retrieving ephemeral public key fails": {
			state: state.Recovery,
			recovery: func(_ *zap.Logger) recovery.Recovery {
				return &stubRecovery{
					ephemeralPublicKeyErr: assert.AnError,
				}
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			log := zaptest.NewLogger(t)

			api := &ClientAPI{
				recovery: tc.recovery(log),
				core: &fakeCore{
					state: tc.state,
				},
				log: log,
			}

			keyDER, err := api.RecoveryPublicKey(t.Context())
			if tc.wantErr {
				assert.Error(err)
				return
			}

			assert.NoError(err)
			assert.NotNil(keyDER)
		})
	}
}

func TestDecryptRecoverySecret(t *testing.T) {
	plainMessage := []byte("MarbleRun")

	testCases := map[string]struct {
		state    state.State
		recovery recovery.Recovery
		input    []byte
		wantErr  bool
	}{
		"success": {
			state: state.Recovery,
			recovery: &stubRecovery{
				decryptedRecoverySecret: plainMessage,
			},
			input: []byte("encryptedData"),
		},
		"coordinator not in recovery state": {
			state: state.AcceptingManifest,
			recovery: &stubRecovery{
				decryptedRecoverySecret: plainMessage,
			},
			input:   []byte("encryptedData"),
			wantErr: true,
		},
		"decryption fails": {
			state: state.Recovery,
			recovery: &stubRecovery{
				decryptRecoverySecretErr: assert.AnError,
			},
			input:   []byte("encryptedData"),
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			log := zaptest.NewLogger(t)

			api := &ClientAPI{
				recovery: tc.recovery,
				core: &fakeCore{
					state: tc.state,
				},
				log: log,
			}

			decrypted, err := api.DecryptRecoverySecret(t.Context(), tc.input)
			if tc.wantErr {
				assert.Error(err)
				return
			}

			assert.NoError(err)
			assert.Equal(plainMessage, decrypted)
		})
	}
}

func TestRecover(t *testing.T) {
	_, rootCert := test.MustSetupTestCerts(test.RecoveryPrivateKeyOne)
	defaultStore := func() store.Store {
		s := stdstore.New(&seal.MockSealer{}, stubEnabler{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
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
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKeyOne),
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
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKeyOne),
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
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKeyOne),
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
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKeyOne),
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
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKeyOne),
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
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKeyOne),
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
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKeyOne),
		},
		"GetCertificate fails": {
			store: &fakeStore{
				store: func() store.Store {
					s := stdstore.New(&seal.MockSealer{}, stubEnabler{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
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
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKeyOne),
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
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKeyOne),
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
			recoveryKeySig: signData(bytes.Repeat([]byte{0xFF}, 16), test.RecoveryPrivateKeyOne),
			wantErr:        true,
		},
		"manifest defines multiple recovery keys": {
			store: &fakeStore{
				store: func() store.Store {
					s := stdstore.New(&seal.MockSealer{}, stubEnabler{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
					s.SetEncryptionKey([]byte("key"), seal.ModeProductKey) // set encryption key to set seal mode
					wr := wrapper.New(s)
					require.NoError(t, wr.PutCertificate(constants.SKCoordinatorRootCert, rootCert))
					recoveryKey2Str := fmt.Sprintf("\"testRecKey2\": \"%s\",\"testRecKey1\":", strings.ReplaceAll(string(test.RecoveryPublicKeyOne), "\n", "\\n"))
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
			recoveryKeySig: signData(bytes.Repeat([]byte{0x01}, 16), test.RecoveryPrivateKeyOne),
			wantErr:        true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			log := zaptest.NewLogger(t)

			api := &ClientAPI{
				txHandle:  tc.store,
				recovery:  tc.recovery,
				core:      tc.core,
				keyServer: &distributor.Stub{},
				log:       log,
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
