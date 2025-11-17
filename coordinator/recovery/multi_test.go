/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package recovery

import (
	"bytes"
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

			r := NewMultiPartyRecovery(nil, zaptest.NewLogger(t))

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
