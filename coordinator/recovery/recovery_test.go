/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package recovery

import (
	"bytes"
	"errors"
	"testing"

	"github.com/edgelesssys/marblerun/test"
	"github.com/edgelesssys/marblerun/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/zap/zaptest"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestMultiPartyRecoveryMultiWithoutRecoveryData(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// setup mock zaplogger which can be passed to Core
	zapLogger := zaptest.NewLogger(t)

	rStore := &fakeStore{}
	rec := NewMultiPartyRecovery(rStore, zapLogger)

	recoveryKeys := map[string]string{
		"testRecKey1": string(test.RecoveryPublicKeyOne),
		"testRecKey2": string(test.RecoveryPublicKeyTwo),
	}
	_, err := rec.GenerateEncryptionKey(recoveryKeys)
	require.NoError(err)

	recoverySecretMap, _, err := rec.GenerateRecoveryData(recoveryKeys)
	require.NoError(err)
	combinedKey := make([]byte, 32)
	copy(combinedKey, rec.encryptionKey)

	// Decrypt secrets
	recoveryByteMap := make(map[string][]byte, 2)
	recoveryByteMap["testRecKey1"], err = util.DecryptOAEP(test.RecoveryPrivateKeyOne, recoverySecretMap["testRecKey1"])
	require.NoError(err)
	recoveryByteMap["testRecKey2"], err = util.DecryptOAEP(test.RecoveryPrivateKeyTwo, recoverySecretMap["testRecKey2"])
	require.NoError(err)

	// Unset recovery data and compute wanted key
	rec.SecretHashMap = nil
	rStore.wantKey, err = util.XORBytes(recoveryByteMap["testRecKey1"], recoveryByteMap["testRecKey2"])
	require.NoError(err)

	// Upload first valid decrypted secret
	remaining, _, err := rec.RecoverKey(recoveryByteMap["testRecKey1"])
	assert.NoError(err)
	assert.Equal(1, remaining)

	// Upload last correct secret
	remaining, secret, err := rec.RecoverKey(recoveryByteMap["testRecKey2"])
	assert.NoError(err)
	assert.Equal(0, remaining)
	assert.Equal(combinedKey, secret)

	require.NoError(rec.SetRecoveryData(rStore.gotRecoveryData))
	assert.Len(rec.SecretHashMap, 2)
	assert.True(rec.SecretHashMap[Hash(recoveryByteMap["testRecKey1"])])
	assert.True(rec.SecretHashMap[Hash(recoveryByteMap["testRecKey2"])])
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
