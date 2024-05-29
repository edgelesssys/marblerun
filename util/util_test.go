// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package util

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveKey(t *testing.T) {
	assert := assert.New(t)
	key, err := DeriveKey([]byte("secret"), []byte("salt"), 32)
	assert.NoError(err)
	assert.Len(key, 32)
}

func TestMustGetenv(t *testing.T) {
	assert := assert.New(t)

	const name = "EDG_TEST_MUST_GETENV"
	const value = "foo"

	assert.NoError(os.Setenv(name, value))
	assert.Equal(value, MustGetenv(name))
	assert.NoError(os.Unsetenv(name))
}

func TestGetenv(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		envname  string
		set      bool
		value    string
		fallback string
		result   string
	}{
		{"EDG_TEST_GETENV", true, "foo", "bar", "foo"},
		{"EDG_TEST_GETENV2", false, "not set", "bar", "bar"},
		{"EDG_TEST_GETENV3", true, "", "bar", "bar"},
	}
	for _, test := range tests {
		if test.set {
			assert.NoError(os.Setenv(test.envname, test.value))
		}
		assert.Equal(test.result, Getenv(test.envname, test.fallback))
		assert.NoError(os.Unsetenv(test.envname))
	}
}

func TestXORBytes(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	firstValue := []byte{0xD, 0xE, 0xA, 0xD, 0xC, 0x0, 0xD, 0xE}
	secondValue := []byte{0xB, 0xA, 0xD, 0xD, 0xC, 0xA, 0xF, 0xE}
	expectedResult := []byte{0x6, 0x4, 0x7, 0x0, 0x0, 0xa, 0x2, 0x0}

	result, err := XORBytes(firstValue, secondValue)
	require.NoError(err)
	assert.Equal(expectedResult, result)
}

func TestIsRawSGXQuote(t *testing.T) {
	sgxQuoteHeader := make([]byte, 48)
	binary.LittleEndian.PutUint16(sgxQuoteHeader[:2], 3)
	binary.LittleEndian.PutUint16(sgxQuoteHeader[2:4], 2)
	binary.LittleEndian.PutUint32(sgxQuoteHeader[4:8], 0)
	binary.LittleEndian.PutUint16(sgxQuoteHeader[8:10], 1)
	binary.LittleEndian.PutUint16(sgxQuoteHeader[10:12], 1)

	testCases := map[string]struct {
		quote        []byte
		wantRawQuote bool
	}{
		"empty quote": {
			quote:        []byte{},
			wantRawQuote: false,
		},
		"garbage data": {
			quote:        bytes.Repeat([]byte{0x0}, 128),
			wantRawQuote: false,
		},
		"quote with OE header": {
			quote: func() []byte {
				quote := append(bytes.Repeat([]byte{0}, 16), sgxQuoteHeader...)
				binary.LittleEndian.PutUint32(quote[:4], 1)
				binary.LittleEndian.PutUint32(quote[4:8], 2)
				binary.LittleEndian.PutUint64(quote[8:16], uint64(len(quote)-16))
				return quote
			}(),
			wantRawQuote: false,
		},
		"raw SGX quote": {
			quote:        append(sgxQuoteHeader, bytes.Repeat([]byte{0x0}, 128)...),
			wantRawQuote: true,
		},
		"version mismatch": {
			quote: func() []byte {
				quote := append(sgxQuoteHeader, bytes.Repeat([]byte{0x0}, 128)...)
				binary.LittleEndian.PutUint16(quote[:2], 1)
				return quote
			}(),
		},
		"invalid attestation key type": {
			quote: func() []byte {
				quote := append(sgxQuoteHeader, bytes.Repeat([]byte{0x0}, 128)...)
				binary.LittleEndian.PutUint16(quote[2:4], 5)
				return quote
			}(),
		},
		"invalid TEE type": {
			quote: func() []byte {
				quote := append(sgxQuoteHeader, bytes.Repeat([]byte{0x0}, 128)...)
				binary.LittleEndian.PutUint32(quote[4:8], 0x81) // TDX quote type
				return quote
			}(),
		},
		"invalid QE SVN": {
			quote: func() []byte {
				quote := append(sgxQuoteHeader, bytes.Repeat([]byte{0x0}, 128)...)
				binary.LittleEndian.PutUint16(quote[8:10], 0)
				return quote
			}(),
		},
		"invalid PCE SVN": {
			quote: func() []byte {
				quote := append(sgxQuoteHeader, bytes.Repeat([]byte{0x0}, 128)...)
				binary.LittleEndian.PutUint16(quote[10:12], 0)
				return quote
			}(),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			isRawQuote := IsRawSGXQuote(tc.quote)
			assert.Equal(tc.wantRawQuote, isRawQuote)
		})
	}
}
