// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package seal

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrepareCipherText(t *testing.T) {
	testCases := map[string]struct {
		sealedData []byte
		wantErr    bool
	}{
		"valid": {
			sealedData: func() []byte {
				data := []byte("data")
				metadata := []byte("metadata")

				metadataLen := make([]byte, 4)
				binary.LittleEndian.PutUint32(metadataLen, uint32(len(metadata)))
				metadata = append(metadataLen, metadata...)

				return append(metadata, data...)
			}(),
		},
		"invalid metadata length": {
			sealedData: func() []byte {
				data := []byte("data")
				metadata := []byte("metadata")

				metadataLen := make([]byte, 4)
				binary.LittleEndian.PutUint32(metadataLen, uint32(10*len(metadata)))
				metadata = append(metadataLen, metadata...)

				return append(metadata, data...)
			}(),
			wantErr: true,
		},
		"missing metadata": {
			sealedData: func() []byte {
				data := []byte("data")

				metadataLen := make([]byte, 4)
				binary.LittleEndian.PutUint32(metadataLen, uint32(4096))

				return append(metadataLen, data...)
			}(),

			wantErr: true,
		},
		"invalid format": {
			sealedData: []byte("AB"),
			wantErr:    true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			_, _, err := prepareCipherText(tc.sealedData)
			if tc.wantErr {
				assert.Error(err)
			} else {
				assert.NoError(err)
			}
		})
	}
}

func TestSealUnseal(t *testing.T) {
	testCases := map[string]struct {
		metadata, data, encryptionKey, decryptionKey []byte
		wantSealErr, wantUnsealErr                   bool
	}{
		"valid": {
			metadata:      []byte("metadata"),
			data:          []byte("data"),
			encryptionKey: bytes.Repeat([]byte{0x01}, 16),
			decryptionKey: bytes.Repeat([]byte{0x01}, 16),
		},
		"missing encryption key": {
			metadata:      []byte("metadata"),
			data:          []byte("data"),
			decryptionKey: bytes.Repeat([]byte{0x01}, 16),
			wantSealErr:   true,
		},
		"invalid encryption key length": {
			metadata:      []byte("metadata"),
			data:          []byte("data"),
			encryptionKey: bytes.Repeat([]byte{0x01}, 15),
			decryptionKey: bytes.Repeat([]byte{0x01}, 16),
			wantSealErr:   true,
		},
		"missing decryption key": {
			metadata:      []byte("metadata"),
			data:          []byte("data"),
			encryptionKey: bytes.Repeat([]byte{0x01}, 16),
			wantUnsealErr: true,
		},
		"invalid decryption key length": {
			metadata:      []byte("metadata"),
			data:          []byte("data"),
			encryptionKey: bytes.Repeat([]byte{0x01}, 16),
			decryptionKey: bytes.Repeat([]byte{0x01}, 15),
			wantUnsealErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			sealer := NewAESGCMSealer()

			sealer.encryptionKey = tc.encryptionKey
			sealedData, err := sealer.Seal(tc.metadata, tc.data)
			if tc.wantSealErr {
				assert.Error(err)

				if tc.encryptionKey == nil {
					assert.ErrorIs(err, ErrMissingEncryptionKey)
				}
				return
			}
			assert.NoError(err)

			sealer.encryptionKey = tc.decryptionKey
			metadata, data, err := sealer.Unseal(sealedData)
			if tc.wantUnsealErr {
				assert.Error(err)

				if tc.decryptionKey == nil {
					assert.ErrorIs(err, ErrMissingEncryptionKey)
				}
				return
			}
			assert.NoError(err)
			assert.Equal(tc.metadata, metadata)
			assert.Equal(tc.data, data)
		})
	}
}
