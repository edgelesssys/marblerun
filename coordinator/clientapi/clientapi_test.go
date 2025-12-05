/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package clientapi

import (
	"bytes"
	"context"
	"crypto"
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
	"math/big"
	"testing"
	"time"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/edgelesssys/marblerun/coordinator/constants"
	ccrypto "github.com/edgelesssys/marblerun/coordinator/crypto"
	"github.com/edgelesssys/marblerun/coordinator/distributor"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/multiupdate"
	"github.com/edgelesssys/marblerun/coordinator/oid"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store"
	dwrapper "github.com/edgelesssys/marblerun/coordinator/store/distributed/wrapper"
	"github.com/edgelesssys/marblerun/coordinator/store/request"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper/testutil"
	"github.com/edgelesssys/marblerun/coordinator/updatelog"
	"github.com/edgelesssys/marblerun/coordinator/user"
	"github.com/edgelesssys/marblerun/test"
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
	rootCert, intermediateCert := test.MustSetupTestCerts(test.RecoveryPrivateKeyOne)

	prepareDefaultStore := func() store.Store {
		s := stdstore.New(&seal.MockSealer{}, stubEnabler{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
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
				s := stdstore.New(&seal.MockSealer{}, stubEnabler{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
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
				s := stdstore.New(&seal.MockSealer{}, stubEnabler{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
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
				s := stdstore.New(&seal.MockSealer{}, stubEnabler{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
				require.NoError(t, s.Put(request.Manifest, []byte("manifest")))
				require.NoError(t, s.Put(request.ManifestSignature, []byte("signature")))
				return s
			}(),
		},
		"GetRawManifest fails": {
			store: func() store.Store {
				s := stdstore.New(&seal.MockSealer{}, stubEnabler{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
				require.NoError(t, s.Put(request.ManifestSignature, []byte("signature")))
				return s
			}(),
			wantErr: true,
		},
		"GetManifestSignature fails": {
			store: func() store.Store {
				s := stdstore.New(&seal.MockSealer{}, stubEnabler{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
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
				s := stdstore.New(&seal.MockSealer{}, stubEnabler{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
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
				s := stdstore.New(&seal.MockSealer{}, stubEnabler{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
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
				s := stdstore.New(&seal.MockSealer{}, stubEnabler{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
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
				s := stdstore.New(&seal.MockSealer{}, stubEnabler{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
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
				txHandle:   tc.store,
				core:       tc.core,
				recovery:   &stubRecovery{},
				updateLog:  updateLog,
				hsmEnabler: stubEnabler{},
				keyServer:  &distributor.Stub{},
				log:        log,
			}

			wrapper := wrapper.New(tc.store)
			rootCert, rootKey, err := ccrypto.GenerateCert([]string{"localhost"}, "MarbleRun Unit Test Root", nil, nil, nil)
			require.NoError(err)
			intermediateCert, intermediateKey, err := ccrypto.GenerateCert([]string{"localhost"}, "MarbleRun Unit Test Intermediate", nil, rootCert, rootKey)
			require.NoError(err)
			marbleCert, _, err := ccrypto.GenerateCert([]string{"localhost"}, "MarbleRun Unit Test Marble", intermediateKey, nil, nil)
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
			_, rootKey, err := ccrypto.GenerateCert([]string{"localhost"}, "MarbleRun Unit Test Root", nil, nil, nil)
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

func TestVerifyMarble(t *testing.T) {
	marbleRootCert, marbleRootKey, err := ccrypto.GenerateCert(nil, "MarbleRun Unit Test Marble", nil, nil, nil)
	require.NoError(t, err)
	otherRootCert, otherRootKey, err := ccrypto.GenerateCert(nil, "MarbleRun Unit Test Marble", nil, nil, nil)
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

func TestUpdateManifest(t *testing.T) {
	ctx := context.Background()
	testCases := map[string]struct {
		updateManifest manifest.Manifest
		prepareAPI     func(*require.Assertions, *ClientAPI)
		iterGetter     *stubIteratorGetter
		core           *fakeCore
		updater        *user.User
		wantErr        bool
	}{
		"successful update": {
			updateManifest: testUpdateManifest(),
			prepareAPI: func(require *require.Assertions, api *ClientAPI) {
				manifest, err := json.Marshal(testManifest())
				require.NoError(err)
				_, err = api.SetManifest(ctx, manifest)
				require.NoError(err)
			},
			core: &fakeCore{
				state: state.AcceptingManifest,
			},
			updater: func() *user.User {
				u := user.NewUser("admin", mustParseCert(t, test.AdminCert))
				u.Assign(user.NewPermission(user.PermissionUpdateManifest, []string{}))
				return u
			}(),
		},
		"successful multi-party update initialization": {
			updateManifest: testUpdateManifest(),
			prepareAPI: func(require *require.Assertions, api *ClientAPI) {
				mnf := testManifest()
				adminCert2, _ := test.MustGenerateAdminTestCert()
				mnf.Users["admin-2"] = manifest.User{
					Certificate: string(adminCert2),
					Roles:       []string{"manifest-update"},
				}
				manifest, err := json.Marshal(mnf)
				require.NoError(err)
				_, err = api.SetManifest(ctx, manifest)
				require.NoError(err)
			},
			core: &fakeCore{
				state: state.AcceptingManifest,
			},
			updater: func() *user.User {
				u := user.NewUser("admin", mustParseCert(t, test.AdminCert))
				u.Assign(user.NewPermission(user.PermissionUpdateManifest, []string{}))
				return u
			}(),
		},
		"uninitialized core": {
			updateManifest: testUpdateManifest(),
			prepareAPI:     func(_ *require.Assertions, _ *ClientAPI) {},
			core: &fakeCore{
				state: state.Uninitialized,
			},
			updater: user.NewUser("admin", mustParseCert(t, test.AdminCert)),
			wantErr: true,
		},
		"user not permitted": {
			updateManifest: testUpdateManifest(),
			prepareAPI: func(require *require.Assertions, api *ClientAPI) {
				_, err := api.SetManifest(ctx, []byte(test.ManifestJSONWithRecoveryKey))
				require.NoError(err)
			},
			core: &fakeCore{
				state: state.AcceptingManifest,
			},
			updater: user.NewUser("admin", mustParseCert(t, test.AdminCert)),
			wantErr: true,
		},
		"recover keys removed": {
			updateManifest: func() manifest.Manifest {
				manifest := testUpdateManifest()
				manifest.RecoveryKeys = nil
				return manifest
			}(),
			prepareAPI: func(require *require.Assertions, api *ClientAPI) {
				manifest, err := json.Marshal(testManifest())
				require.NoError(err)
				_, err = api.SetManifest(ctx, manifest)
				require.NoError(err)
			},
			core: &fakeCore{
				state: state.AcceptingManifest,
			},
			updater: func() *user.User {
				u := user.NewUser("admin", mustParseCert(t, test.AdminCert))
				u.Assign(user.NewPermission(user.PermissionUpdateManifest, []string{}))
				return u
			}(),
			wantErr: false,
		},
		"changed recovery keys": {
			updateManifest: func() manifest.Manifest {
				manifest := testUpdateManifest()
				manifest.RecoveryKeys = map[string]string{
					"newKey": string(test.RecoveryPublicKeyOne),
				}
				return manifest
			}(),
			prepareAPI: func(require *require.Assertions, api *ClientAPI) {
				manifest, err := json.Marshal(testManifest())
				require.NoError(err)
				_, err = api.SetManifest(ctx, manifest)
				require.NoError(err)
			},
			core: &fakeCore{
				state: state.AcceptingManifest,
			},
			updater: func() *user.User {
				u := user.NewUser("admin", mustParseCert(t, test.AdminCert))
				u.Assign(user.NewPermission(user.PermissionUpdateManifest, []string{}))
				return u
			}(),
			wantErr: false,
		},
		"changed recovery threshold": {
			updateManifest: func() manifest.Manifest {
				manifest := testUpdateManifest()
				manifest.RecoveryKeys["key2"] = manifest.RecoveryKeys["key"]
				manifest.RecoveryKeys["key3"] = manifest.RecoveryKeys["key"]
				manifest.Config.RecoveryThreshold = 2
				return manifest
			}(),
			prepareAPI: func(require *require.Assertions, api *ClientAPI) {
				// set up manifest with 3 recovery keys
				manifest := testManifest()
				manifest.RecoveryKeys["key2"] = manifest.RecoveryKeys["key"]
				manifest.RecoveryKeys["key3"] = manifest.RecoveryKeys["key"]
				manifest.Config.RecoveryThreshold = 3
				manifestJSON, err := json.Marshal(manifest)
				require.NoError(err)
				_, err = api.SetManifest(ctx, manifestJSON)
				require.NoError(err)
			},
			core: &fakeCore{
				state: state.AcceptingManifest,
			},
			updater: func() *user.User {
				u := user.NewUser("admin", mustParseCert(t, test.AdminCert))
				u.Assign(user.NewPermission(user.PermissionUpdateManifest, []string{}))
				return u
			}(),
			wantErr: false,
		},
		"symmetric secret file": {
			updateManifest: func() manifest.Manifest {
				mnf := testManifest()
				mnf.Secrets["symmetric"] = manifest.Secret{
					Type: manifest.SecretTypeSymmetricKey,
					Size: 128,
				}
				marble := mnf.Marbles["marble-a"]
				marble.Parameters.Files = map[string]manifest.File{
					"symmetric": {
						Data:     "{{ hex .Secrets.symmetric }}",
						Encoding: "string",
					},
				}
				mnf.Marbles["marble-a"] = marble

				mnf.Roles["newRole"] = manifest.Role{
					ResourceType:  "Packages",
					ResourceNames: []string{"package-a"},
					Actions:       []string{"UpdateSecurityVersion"},
				}

				return mnf
			}(),
			prepareAPI: func(require *require.Assertions, api *ClientAPI) {
				mnf := testManifest()
				mnf.Secrets["symmetric"] = manifest.Secret{
					Type: manifest.SecretTypeSymmetricKey,
					Size: 128,
				}
				marble := mnf.Marbles["marble-a"]
				marble.Parameters.Files = map[string]manifest.File{
					"symmetric": {
						Data:     "{{ hex .Secrets.symmetric }}",
						Encoding: "string",
					},
				}
				mnf.Marbles["marble-a"] = marble

				manifest, err := json.Marshal(mnf)
				require.NoError(err)
				_, err = api.SetManifest(ctx, manifest)
				require.NoError(err)
			},
			core: &fakeCore{
				state: state.AcceptingManifest,
			},
			updater: func() *user.User {
				u := user.NewUser("admin", mustParseCert(t, test.AdminCert))
				u.Assign(user.NewPermission(user.PermissionUpdateManifest, []string{}))
				return u
			}(),
			wantErr: false,
		},
		"invalid template in manifest": {
			updateManifest: func() manifest.Manifest {
				mnf := testUpdateManifest()
				marble := mnf.Marbles["marble-a"]
				marble.Parameters.Files = map[string]manifest.File{
					"file": {
						Data:     "{{ hex .Secrets.doesNotExist }}",
						Encoding: "string",
					},
				}
				mnf.Marbles["marble-a"] = marble

				return mnf
			}(),
			prepareAPI: func(require *require.Assertions, api *ClientAPI) {
				manifest, err := json.Marshal(testManifest())
				require.NoError(err)
				_, err = api.SetManifest(ctx, manifest)
				require.NoError(err)
			},
			core: &fakeCore{
				state: state.AcceptingManifest,
			},
			updater: func() *user.User {
				u := user.NewUser("admin", mustParseCert(t, test.AdminCert))
				u.Assign(user.NewPermission(user.PermissionUpdateManifest, []string{}))
				return u
			}(),
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			api, _ := setupAPI(t, tc.core)
			getPending := func() (*multiupdate.MultiPartyUpdate, error) {
				t.Helper()
				tx, rollback, _, err := dwrapper.WrapTransaction(ctx, api.txHandle)
				require.NoError(err)
				defer rollback()
				return tx.GetPendingUpdate()
			}
			testSecret := func(name string) {
				t.Helper()
				tx, rollback, _, err := wrapper.WrapTransaction(ctx, api.txHandle)
				require.NoError(err)
				defer rollback()
				_, err = tx.GetSecret(name)
				assert.NoError(err)
			}

			tc.prepareAPI(require, api)

			updateManifest, err := json.Marshal(tc.updateManifest)
			require.NoError(err)

			_, _, _, err = api.UpdateManifest(ctx, updateManifest, tc.updater)
			if tc.wantErr {
				assert.Error(err)
				time.Sleep(50 * time.Millisecond) // Short wait since the clean up is async.
				_, err := getPending()
				assert.ErrorIs(err, store.ErrValueUnset)
				return
			}

			assert.NoError(err)

			pendingUpdate, err := getPending()
			if err == nil {
				assert.Greater(pendingUpdate.MissingAcknowledgments(), 0)
				assert.Equal(updateManifest, pendingUpdate.Manifest())
				return
			}

			require.ErrorIs(err, store.ErrValueUnset)
			newManifest := testutil.GetRawManifest(t, api.txHandle)
			assert.Equal(updateManifest, newManifest)

			// Check that all secrets set in the update manifest have been
			// generated and stored.
			for name := range tc.updateManifest.Secrets {
				testSecret(name)
			}
			_, err = getPending()
			assert.ErrorIs(err, store.ErrValueUnset)
		})
	}
}

func TestMultiPartyUpdate(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	ctx := context.Background()

	mnf := testManifest()
	adminCert2, _ := test.MustGenerateAdminTestCert()
	adminCert3, _ := test.MustGenerateAdminTestCert()
	mnf.Users["admin-2"] = manifest.User{
		Certificate: string(adminCert2),
		Roles:       []string{"manifest-update"},
	}
	mnf.Users["admin-3"] = manifest.User{
		Certificate: string(adminCert3),
		Roles:       []string{"manifest-update"},
	}
	updateMnf := testUpdateManifest()

	mnfJSON, err := json.Marshal(mnf)
	require.NoError(err)
	updateMnfJSON, err := json.Marshal(updateMnf)
	require.NoError(err)

	api, _ := setupAPI(t, &fakeCore{state: state.AcceptingManifest})

	// No pending update before we set a manifest
	_, err = api.GetPendingUpdate(ctx)
	assert.Error(err)

	_, err = api.SetManifest(ctx, mnfJSON)
	require.NoError(err)

	admin1 := testutil.GetUser(t, api.txHandle, "admin")
	admin2 := testutil.GetUser(t, api.txHandle, "admin-2")
	admin3 := testutil.GetUser(t, api.txHandle, "admin-3")

	// No pending update
	_, err = api.GetPendingUpdate(ctx)
	assert.Error(err)

	// try to cancel update, should fail
	err = api.CancelPendingUpdate(ctx, admin1)
	assert.Error(err)

	// try to acknowledge update, should fail
	_, _, _, err = api.AcknowledgePendingUpdate(ctx, updateMnfJSON, admin1)
	assert.Error(err)

	// Initialize update with first admin
	_, missingUsers, missingAcks, err := api.UpdateManifest(ctx, updateMnfJSON, admin1)
	require.NoError(err)

	pendingUpdate := getPendingUpdate(t, api.txHandle)
	assert.Equal(updateMnfJSON, pendingUpdate.Manifest())
	assert.Equal(2, pendingUpdate.MissingAcknowledgments())
	assert.Equal(2, missingAcks)
	assert.ElementsMatch(pendingUpdate.MissingUsers(), missingUsers)

	// Check the pending update
	pending, err := api.GetPendingUpdate(ctx)
	require.NoError(err)
	assert.Equal(updateMnfJSON, pending.Manifest())
	assert.Equal(2, pending.MissingAcknowledgments())

	// Try to acknowledge with first admin, should do nothing
	_, missing, missingAcks, err := api.AcknowledgePendingUpdate(ctx, updateMnfJSON, admin1)
	assert.NoError(err)
	assert.ElementsMatch([]string{admin2.Name(), admin3.Name()}, missing)
	assert.Equal(2, missingAcks)

	// Try to overwrite the pending update by starting a new update, should fail
	_, _, _, err = api.UpdateManifest(ctx, updateMnfJSON, admin1)
	assert.Error(err)
	_, _, _, err = api.UpdateManifest(ctx, []byte(test.UpdateManifest), admin1)
	assert.Error(err)

	// Acknowledge with different manifest, should fail
	_, _, _, err = api.AcknowledgePendingUpdate(ctx, mnfJSON, admin2)
	assert.Error(err)

	// Acknowledge with second admin
	_, missing, missingAcks, err = api.AcknowledgePendingUpdate(ctx, updateMnfJSON, admin2)
	require.NoError(err)
	assert.ElementsMatch([]string{admin3.Name()}, missing)
	assert.Equal(1, missingAcks)

	// Acknowledge with third admin
	_, missing, missingAcks, err = api.AcknowledgePendingUpdate(ctx, updateMnfJSON, admin3)
	require.NoError(err)
	assert.Len(missing, 0)
	assert.Equal(0, missingAcks)

	// Check that the update is applied
	newManifest := testutil.GetRawManifest(t, api.txHandle)
	assert.Equal(updateMnfJSON, newManifest)

	// Check that the pending update is cleared
	_, err = api.GetPendingUpdate(ctx)
	assert.Error(err)

	// Start a new update and try to cancel it
	_, missingUsers, missingAcks, err = api.UpdateManifest(ctx, updateMnfJSON, admin1)
	require.NoError(err)

	pendingUpdate = getPendingUpdate(t, api.txHandle)
	assert.Equal(updateMnfJSON, pendingUpdate.Manifest())
	assert.Equal(2, pendingUpdate.MissingAcknowledgments())
	assert.Equal(2, missingAcks)
	assert.ElementsMatch(pendingUpdate.MissingUsers(), missingUsers)

	err = api.CancelPendingUpdate(ctx, admin1)
	require.NoError(err)

	// Check that the pending update is cleared
	_, err = api.GetPendingUpdate(ctx)
	assert.Error(err)
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

func (c *fakeCore) GenerateSecrets(newSecrets map[string]manifest.Secret, id uuid.UUID, _ string, rootCert *x509.Certificate, privK *ecdsa.PrivateKey, _ *ecdsa.PrivateKey,
) (map[string]manifest.Secret, error) {
	if c.generateSecretsErr != nil {
		return nil, c.generateSecretsErr
	}

	secrets := make(map[string]manifest.Secret, len(newSecrets))
	for name, secret := range newSecrets {
		if secret.UserDefined {
			continue
		}

		if secret.Shared != (id == uuid.Nil) {
			continue
		}

		switch secret.Type {
		case manifest.SecretTypeSymmetricKey:
			secret.Public = bytes.Repeat([]byte{0x12, 0x34}, 16)
			secret.Private = bytes.Repeat([]byte{0x56, 0x78}, 16)
		case manifest.SecretTypeCertECDSA, manifest.SecretTypeCertED25519, manifest.SecretTypeCertRSA:
			cert, key, err := ccrypto.GenerateCert([]string{"localhost"}, name, nil, rootCert, privK)
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
	ephemeralPublicKey       crypto.PublicKey
	ephemeralPublicKeyErr    error
	decryptedRecoverySecret  []byte
	decryptRecoverySecretErr error
}

func (s *stubRecovery) GenerateEncryptionKey(_ map[string]string, _ uint) ([]byte, error) {
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

func (s *stubRecovery) EphemeralPublicKey() (crypto.PublicKey, error) {
	return s.ephemeralPublicKey, s.ephemeralPublicKeyErr
}

func (s *stubRecovery) DecryptRecoverySecret(_ []byte) ([]byte, error) {
	return s.decryptedRecoverySecret, s.decryptRecoverySecretErr
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

type stubIteratorGetter struct {
	*stdstore.StdStore

	iterator       *stubIterator
	getIteratorErr error
}

func (s *stubIteratorGetter) Iterator(string) (store.Iterator, error) {
	return s.iterator, s.getIteratorErr
}

type stubIterator struct {
	idx        int
	keys       []string
	getNextErr error
}

// GetNext implements the Iterator interface.
func (i *stubIterator) GetNext() (string, error) {
	if i.getNextErr != nil {
		return "", i.getNextErr
	}
	if i.idx >= len(i.keys) {
		return "", errors.New("index out of range")
	}
	val := i.keys[i.idx]
	i.idx++
	return val, nil
}

// HasNext implements the Iterator interface.
func (i *stubIterator) HasNext() bool {
	return i.idx < len(i.keys)
}

// mustParseCert parses a PEM-encoded certificate.
func mustParseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func testManifest() manifest.Manifest {
	return manifest.Manifest{
		Packages: map[string]quote.PackageProperties{
			"package-a": {
				UniqueID: "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
			},
		},
		Marbles: map[string]manifest.Marble{
			"marble-a": {
				Package: "package-a",
				Parameters: manifest.Parameters{
					Argv: []string{"test"},
				},
			},
		},
		Secrets: map[string]manifest.Secret{
			"secret-b": {
				Type:   manifest.SecretTypeSymmetricKey,
				Size:   32,
				Shared: true,
			},
			"secret-c": {
				Type:        manifest.SecretTypePlain,
				UserDefined: true,
			},
		},
		Users: map[string]manifest.User{
			"admin": {
				Certificate: string(test.AdminCert),
				Roles:       []string{"manifest-update"},
			},
		},
		Roles: map[string]manifest.Role{
			"manifest-update": {
				ResourceType: "Manifest",
				Actions:      []string{user.PermissionUpdateManifest},
			},
		},
		RecoveryKeys: map[string]string{
			"key": string(test.RecoveryPublicKeyOne),
		},
		TLS: map[string]manifest.TLStag{
			"tls-tag": {
				Outgoing: []manifest.TLSTagEntry{
					{
						Addr: "192.0.2.2",
						Port: "443",
					},
				},
				Incoming: []manifest.TLSTagEntry{
					{
						Addr: "192.0.2.3",
						Port: "443",
					},
				},
			},
		},
	}
}

func testUpdateManifest() manifest.Manifest {
	mnf := testManifest()
	mnf.Packages["package-a"] = quote.PackageProperties{
		UniqueID: "2f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
	}
	mnf.Packages["package-b"] = quote.PackageProperties{
		UniqueID: "3f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
	}
	managerCert, _ := test.MustGenerateAdminTestCert()
	adminCert2, _ := test.MustGenerateAdminTestCert()
	adminCert3, _ := test.MustGenerateAdminTestCert()
	mnf.Users["manager"] = manifest.User{
		Certificate: string(managerCert),
		Roles: []string{
			"packageUpdate",
			"secretRead",
		},
	}
	mnf.Users["admin-2"] = manifest.User{
		Certificate: string(adminCert2),
		Roles:       []string{"manifest-update"},
	}
	mnf.Users["admin-3"] = manifest.User{
		Certificate: string(adminCert3),
		Roles:       []string{"manifest-update"},
	}
	mnf.Roles["packageUpdate"] = manifest.Role{
		ResourceType:  "Packages",
		ResourceNames: []string{"package-a", "package-b"},
		Actions:       []string{user.PermissionUpdatePackage},
	}
	mnf.Roles["secretRead"] = manifest.Role{
		ResourceType:  "Secrets",
		ResourceNames: []string{"secret-b"},
		Actions:       []string{user.PermissionReadSecret},
	}
	return mnf
}

// getPendingUpdate returns the pending update from store.
func getPendingUpdate(t *testing.T, txHandle transactionHandle) *multiupdate.MultiPartyUpdate {
	t.Helper()
	tx, rollback, _, err := dwrapper.WrapTransaction(context.Background(), txHandle)
	require.NoError(t, err)
	defer rollback()
	update, err := tx.GetPendingUpdate()
	require.NoError(t, err)
	return update
}

type stubEnabler struct{}

func (stubEnabler) SetEnabled(_ bool) {}
