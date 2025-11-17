/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package recovery_test // Separate package to avoid import cycles

import (
	"bytes"
	"context"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/clientapi"
	"github.com/edgelesssys/marblerun/coordinator/core"
	"github.com/edgelesssys/marblerun/coordinator/distributor"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store/distributed/wrapper"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/edgelesssys/marblerun/test"
	"github.com/edgelesssys/marblerun/util"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestMultiPartyRecoveryMultiWithoutRecoveryData(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	ctx := context.Background()

	// setup mock zaplogger which can be passed to Core
	zapLogger := zaptest.NewLogger(t)

	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	fs := afero.NewMemMapFs()
	rStore := &fakeStore{}
	rec := recovery.NewMultiPartyRecovery(rStore, zapLogger)
	cStore := stdstore.New(sealer, fs, "", zapLogger)

	c, err := core.NewCore([]string{"localhost"}, validator, issuer, cStore, rec, zapLogger, nil, nil)
	require.NoError(err)
	clientAPI, err := clientapi.New(cStore, rec, c, &distributor.Stub{}, zapLogger)
	require.NoError(err)

	// new core does not allow recover
	key, sig := recoveryKeyWithSignature(t, test.RecoveryPrivateKeyOne)
	_, err = clientAPI.Recover(ctx, key, sig)
	assert.Errorf(err, "server is not in expected state")

	// Set manifest. This will seal the state.
	recoverySecretMap, err := clientAPI.SetManifest(ctx, []byte(test.ManifestJSONWithRecoveryKeys))
	require.NoError(err)

	// core does not allow recover after manifest has been set
	_, err = clientAPI.Recover(ctx, key, sig)
	assert.Errorf(err, "server is not in expected state")

	// Initialize new core and let unseal fail
	sealer.UnsealError = &seal.EncryptionKeyError{}
	c2Store := stdstore.New(sealer, fs, "", zapLogger)
	c2, err := core.NewCore([]string{"localhost"}, validator, issuer, c2Store, rec, zapLogger, nil, nil)
	sealer.UnsealError = nil
	require.NoError(err)
	clientAPI, err = clientapi.New(c2Store, rec, c2, &distributor.Stub{}, zapLogger)
	require.NoError(err)
	c2State, err := wrapper.New(c2Store).GetState()
	assert.NoError(err)
	require.Equal(state.Recovery, c2State)

	// Decrypt secrets
	recoveryByteMap := make(map[string][]byte, 2)
	recoveryByteMap["testRecKey1"], err = util.DecryptOAEP(test.RecoveryPrivateKeyOne, recoverySecretMap["testRecKey1"])
	require.NoError(err)
	sig1, err := util.SignPKCS1v15(test.RecoveryPrivateKeyOne, recoveryByteMap["testRecKey1"])
	require.NoError(err)
	recoveryByteMap["testRecKey2"], err = util.DecryptOAEP(test.RecoveryPrivateKeyTwo, recoverySecretMap["testRecKey2"])
	require.NoError(err)
	sig2, err := util.SignPKCS1v15(test.RecoveryPrivateKeyTwo, recoveryByteMap["testRecKey2"])
	require.NoError(err)

	// Unset recovery data and compute wanted key
	rec.SecretHashMap = nil
	rStore.wantKey, err = util.XORBytes(recoveryByteMap["testRecKey1"], recoveryByteMap["testRecKey2"])
	require.NoError(err)

	// Upload first valid decrypted secret
	_, err = clientAPI.Recover(ctx, recoveryByteMap["testRecKey1"], sig1)
	assert.NoError(err)

	// Upload same key again, should be accepted
	_, err = clientAPI.Recover(ctx, recoveryByteMap["testRecKey1"], sig1)
	assert.NoError(err)

	// Upload some garbage in between
	_, err = clientAPI.Recover(ctx, make([]byte, 32), sig1)
	assert.NoError(err)

	// Upload last correct secret again, coordinator should not be recovered because an incorrect secret was uploaded
	_, err = clientAPI.Recover(ctx, recoveryByteMap["testRecKey2"], sig2)
	assert.Error(err)
	c2State, err = wrapper.New(c2Store).GetState()
	assert.NoError(err)
	// Coordinator should still be in recovery state
	assert.Equal(state.Recovery, c2State)

	// Lets retry the recovery with only the correct secrets
	// Upload first valid decrypted secret
	_, err = clientAPI.Recover(ctx, recoveryByteMap["testRecKey1"], sig1)
	assert.NoError(err)
	// Upload last correct secret, this time the coordinator should be recovered successfully
	_, err = clientAPI.Recover(ctx, recoveryByteMap["testRecKey2"], sig2)
	assert.NoError(err)
	c2State, err = wrapper.New(c2Store).GetState()
	assert.NoError(err)
	assert.Equal(state.AcceptingMarbles, c2State)

	// Verify persisted recovery data
	require.NoError(rec.SetRecoveryData(rStore.gotRecoveryData))
	assert.Len(rec.SecretHashMap, 2)
	assert.True(rec.SecretHashMap[recovery.Hash(recoveryByteMap["testRecKey1"])])
	assert.True(rec.SecretHashMap[recovery.Hash(recoveryByteMap["testRecKey2"])])
}

type fakeStore struct {
	wantKey         []byte
	gotRecoveryData []byte
}

func (*fakeStore) GetCiphertext() ([]byte, error) {
	return []byte("ciphertext"), nil
}

func (s *fakeStore) TestKey(key, ciphertext []byte) bool {
	return bytes.Equal(key, s.wantKey) && bytes.Equal(ciphertext, []byte("ciphertext"))
}

func (s *fakeStore) PersistRecoveryData(recoveryData []byte) error {
	s.gotRecoveryData = recoveryData
	return errors.New("this error should only be logged")
}

func recoveryKeyWithSignature(t *testing.T, priv *rsa.PrivateKey) ([]byte, []byte) {
	t.Helper()
	key := make([]byte, 16)
	sig, err := util.SignPKCS1v15(priv, key)
	require.NoError(t, err)
	return key, sig
}
