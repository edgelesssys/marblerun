// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This is a demo dump of a .note.sgxmeta from a signed Occlum ELF enclave file ("libocclum-libos.signed.so")
// To decode: Base64 Decode -> zlib Decompress -> raw data.
const sgxMetaDataSample = "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"

func TestParseSigStruct(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Decode & Decompress test data
	sgxMetaDataCompressed, err := base64.RawStdEncoding.DecodeString(sgxMetaDataSample)
	require.NoError(err)
	r, err := zlib.NewReader(bytes.NewReader(sgxMetaDataCompressed))
	require.NoError(err)
	defer r.Close()
	sgxMetaData, err := io.ReadAll(r)
	require.NoError(err)

	// Parse SIGSTRUCT and verify against known results
	mrenclave, mrsigner, isvprodid, isvsvn, err := parseSigStruct(sgxMetaData)
	assert.NoError(err)
	assert.Equal("9d0dc627f893fc5471c8089d621a3da3652cf4e67eece9143ec5656406275a26", hex.EncodeToString(mrenclave))
	assert.Equal("83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e", hex.EncodeToString(mrsigner))
	assert.EqualValues(0, binary.LittleEndian.Uint16(isvprodid))
	assert.EqualValues(0, binary.LittleEndian.Uint16(isvsvn))
}
