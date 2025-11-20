/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package recovery

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/edgelesssys/marblerun/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestMultiPartyRecover(t *testing.T) {
	type sut struct {
		recoverySecret []byte
		keyShare       []byte
		assert         func(*assert.Assertions, *MultiPartyRecovery, int, []byte, error)
	}

	testCases := map[string]struct {
		testStructs []sut
	}{
		"single recovery key": {
			testStructs: []sut{
				{
					recoverySecret: bytes.Repeat([]byte{0x01}, 16),
					keyShare:       bytes.Repeat([]byte{0x01}, 16),
					assert: func(assert *assert.Assertions, r *MultiPartyRecovery, remaining int, combinedKey []byte, err error) {
						assert.True(r.SecretHashMap[Hash(bytes.Repeat([]byte{0x01}, 16))]) // cleanup was called
						assert.Equal(0, r.correctSecrets)                                  // cleanup was called
						assert.Equal(0, remaining)
						assert.Equal(bytes.Repeat([]byte{0x01}, 16), combinedKey)
						assert.NoError(err)
					},
				},
			},
		},
		"multiple recovery keys": {
			testStructs: func() []sut {
				secret1 := bytes.Repeat([]byte{0x01}, 16)
				secret2 := bytes.Repeat([]byte{0x02}, 16)
				secret3 := bytes.Repeat([]byte{0x03}, 16)
				combinedRecoveryKey, err := util.XORBytes(secret1, secret2)
				require.NoError(t, err)
				combinedRecoveryKey, err = util.XORBytes(combinedRecoveryKey, secret3)
				require.NoError(t, err)

				return []sut{
					{
						recoverySecret: secret1,
						keyShare:       secret1,
						assert: func(assert *assert.Assertions, r *MultiPartyRecovery, remaining int, combinedKey []byte, err error) {
							assert.False(r.SecretHashMap[Hash(secret1)])
							assert.Equal(1, r.correctSecrets)
							assert.Equal(2, remaining)
							assert.Nil(combinedKey)
							assert.NoError(err)
						},
					},
					{
						recoverySecret: secret2,
						keyShare:       secret2,
						assert: func(assert *assert.Assertions, r *MultiPartyRecovery, remaining int, combinedKey []byte, err error) {
							assert.False(r.SecretHashMap[Hash(secret2)])
							assert.Equal(2, r.correctSecrets)
							assert.Equal(1, remaining)
							assert.Nil(combinedKey)
							assert.NoError(err)
						},
					},
					{
						recoverySecret: secret3,
						keyShare:       secret3,
						assert: func(assert *assert.Assertions, r *MultiPartyRecovery, remaining int, combinedKey []byte, err error) {
							assert.True(r.SecretHashMap[Hash(secret3)]) // cleanup was called
							assert.Equal(0, r.correctSecrets)           // cleanup was called
							assert.Equal(0, remaining)
							assert.Equal(combinedRecoveryKey, combinedKey)
							assert.NoError(err)
						},
					},
				}
			}(),
		},
		"invalid secret": {
			testStructs: []sut{
				{
					recoverySecret: bytes.Repeat([]byte{0xFF}, 16),
					keyShare:       bytes.Repeat([]byte{0x01}, 16),
					assert: func(assert *assert.Assertions, r *MultiPartyRecovery, remaining int, combinedKey []byte, err error) {
						assert.True(r.SecretHashMap[Hash(bytes.Repeat([]byte{0x01}, 16))])
						assert.Equal(0, r.correctSecrets)
						assert.Equal(1, remaining)
						assert.Nil(combinedKey)
						assert.Error(err)
					},
				},
			},
		},
		"xor error": {
			testStructs: []sut{
				{
					recoverySecret: bytes.Repeat([]byte{0xFF}, 12),
					keyShare:       bytes.Repeat([]byte{0xFF}, 12),
					assert: func(assert *assert.Assertions, r *MultiPartyRecovery, remaining int, combinedKey []byte, err error) {
						assert.True(r.SecretHashMap[Hash(bytes.Repeat([]byte{0xFF}, 12))])
						assert.Equal(0, r.correctSecrets)
						assert.Equal(1, remaining)
						assert.Nil(combinedKey)
						assert.Error(err)
					},
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			r := New(nil, zaptest.NewLogger(t))

			r.SecretHashMap = make(map[string]bool, len(tc.testStructs))
			for _, testStruct := range tc.testStructs {
				r.SecretHashMap[Hash(testStruct.keyShare)] = true
			}

			for _, testStruct := range tc.testStructs {
				remaining, combinedKey, err := r.RecoverKey(testStruct.recoverySecret)
				testStruct.assert(assert, r, remaining, combinedKey, err)
			}
		})
	}
}

func TestShamirRecovery(t *testing.T) {
	log := zaptest.NewLogger(t)

	rStore := &fakeStore{}
	rec := New(rStore, log)

	recoveryKeysPub := map[string]string{}
	recoveryKeysPriv := []struct {
		name    string
		privKey *rsa.PrivateKey
	}{}
	for i := range 10 {
		recPEM, recPriv := generateRecoveryKey(t)
		keyName := fmt.Sprintf("testRecKey%d", i+1)
		recoveryKeysPub[keyName] = string(recPEM)
		recoveryKeysPriv = append(recoveryKeysPriv, struct {
			name    string
			privKey *rsa.PrivateKey
		}{keyName, recPriv})
	}

	encryptionKey, err := rec.GenerateEncryptionKey(recoveryKeysPub, 3)
	require.NoError(t, err)
	rStore.wantKey = encryptionKey

	recoverySecretMap, _, err := rec.GenerateRecoveryData(recoveryKeysPub)
	require.NoError(t, err)

	// Try out all combinations
	for i := range recoveryKeysPriv {
		t.Run(fmt.Sprintf("combination_%d", i), func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			idx1 := i % len(recoveryKeysPriv)
			idx2 := (i + 1) % len(recoveryKeysPriv)
			idx3 := (i + 2) % len(recoveryKeysPriv)

			// Decrypt secrets
			firstRecoverySecret, err := util.DecryptOAEP(recoveryKeysPriv[idx1].privKey, recoverySecretMap[recoveryKeysPriv[idx1].name])
			require.NoError(err)
			secondRecoverySecret, err := util.DecryptOAEP(recoveryKeysPriv[idx2].privKey, recoverySecretMap[recoveryKeysPriv[idx2].name])
			require.NoError(err)
			thirdRecoverySecret, err := util.DecryptOAEP(recoveryKeysPriv[idx3].privKey, recoverySecretMap[recoveryKeysPriv[idx3].name])
			require.NoError(err)

			remaining, _, err := rec.RecoverKey(firstRecoverySecret)
			assert.NoError(err)
			assert.Equal(len(recoveryKeysPriv)-1, remaining) // With shamir recovery, we only know the maximum number of required secrets

			remaining, _, err = rec.RecoverKey(secondRecoverySecret)
			assert.NoError(err)
			assert.Equal(len(recoveryKeysPriv)-2, remaining)

			remaining, recoveredKey, err := rec.RecoverKey(thirdRecoverySecret)
			assert.NoError(err)
			assert.Equal(0, remaining)
			assert.Equal(encryptionKey, recoveredKey)
		})
	}

	t.Run("duplicate secret", func(t *testing.T) {
		assert := assert.New(t)

		// Decrypt secret
		firstRecoverySecret, err := util.DecryptOAEP(recoveryKeysPriv[0].privKey, recoverySecretMap[recoveryKeysPriv[0].name])
		require.NoError(t, err)

		remaining, _, err := rec.RecoverKey(firstRecoverySecret)
		assert.NoError(err)
		assert.Equal(len(recoveryKeysPriv)-1, remaining)

		// Provide same secret again
		remaining, _, err = rec.RecoverKey(firstRecoverySecret)
		assert.Error(err)
		assert.Equal(len(recoveryKeysPriv)-1, remaining) // should not have changed

		rec.cleanup()
	})

	t.Run("invalid secret", func(t *testing.T) {
		assert := assert.New(t)

		invalidSecret := bytes.Repeat([]byte{0xFF}, 33)
		remaining, _, err := rec.RecoverKey(invalidSecret)
		assert.Error(err)
		assert.Equal(len(recoveryKeysPriv), remaining)
	})
}

func generateRecoveryKey(t *testing.T) (publicKeyPem []byte, privateKey *rsa.PrivateKey) {
	t.Helper()
	require := require.New(t)
	key, err := rsa.GenerateKey(rand.Reader, 3096)
	require.NoError(err)

	pkixPublicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(err)

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkixPublicKey,
	}

	return pem.EncodeToMemory(publicKeyBlock), key
}
