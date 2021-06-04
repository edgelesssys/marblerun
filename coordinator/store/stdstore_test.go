// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestStdStore(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	zap, err := zap.NewDevelopment()
	require.NoError(err)
	store := NewStdStore(&seal.MockSealer{}, zap)

	testData1 := []byte("test data")
	testData2 := []byte("more test data")

	// request unset value
	_, err = store.Get("test:input")
	assert.Error(err)

	// test Put method
	err = store.Put("test:input", testData1)
	assert.NoError(err)
	err = store.Put("another:input", testData2)
	assert.NoError(err)

	// make sure values have been set
	val, err := store.Get("test:input")
	assert.NoError(err)
	assert.Equal(testData1, val)
	val, err = store.Get("another:input")
	assert.NoError(err)
	assert.Equal(testData2, val)
}

func TestStdStoreSealing(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	zap, err := zap.NewDevelopment()
	require.NoError(err)
	sealer := &seal.MockSealer{}
	store := NewStdStore(sealer, zap)

	testData1 := []byte("test data")
	store.Put("test:input", testData1)
	assert.NoError(err)

	err = store.SealState([]byte{0x00})
	assert.NoError(err)

	// Check sealing with a new store initialized with the sealed state
	store2 := NewStdStore(sealer, zap)
	_, err = store2.LoadState()
	assert.NoError(err)
	val, err := store2.Get("test:input")
	assert.NoError(err)
	assert.Equal(testData1, val)
}

func TestStdStoreRollback(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	zap, err := zap.NewDevelopment()
	require.NoError(err)
	store := NewStdStore(&seal.MockSealer{}, zap)

	testData1 := []byte("test data")
	testData2 := []byte("more test data")

	// save data to store and seal
	err = store.Put("test:input", testData1)
	assert.NoError(err)
	err = store.SealState([]byte{0x00})
	assert.NoError(err)

	// save more data to store
	err = store.Put("another:input", testData2)
	assert.NoError(err)

	// reload state and verify only testData1 exists
	_, err = store.LoadState()
	assert.NoError(err)
	val, err := store.Get("test:input")
	assert.NoError(err)
	assert.Equal(testData1, val)
	_, err = store.Get("another:input")
	assert.Error(err)
}
