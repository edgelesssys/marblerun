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
	recData, err := store.LoadState()
	assert.NoError(err)

	testData1 := []byte("test data")
	testData2 := []byte("more test data")

	// request unset value
	_, err = store.Get("test:input")
	assert.Error(err)

	// test Put method
	err = store.BeginTransaction()
	assert.NoError(err)
	err = store.Put("test:input", testData1)
	assert.NoError(err)
	err = store.Put("another:input", testData2)
	assert.NoError(err)
	err = store.Commit(recData)

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
	recoveryData, err := store.LoadState()
	assert.NoError(err)

	err = store.BeginTransaction()
	assert.NoError(err)
	testData1 := []byte("test data")
	store.Put("test:input", testData1)
	assert.NoError(err)

	err = store.Commit(recoveryData)
	assert.NoError(err)

	// Check sealing with a new store initialized with the sealed state
	store2 := NewStdStore(sealer, zap)
	recoveryData, err = store2.LoadState()
	assert.NoError(err)
	err = store2.Commit(recoveryData)
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
	recoveryData, err := store.LoadState()
	assert.NoError(err)

	testData1 := []byte("test data")
	testData2 := []byte("more test data")
	testData3 := []byte("and even more data")

	// save data to store and seal
	err = store.BeginTransaction()
	assert.NoError(err)
	err = store.Put("test:input", testData1)
	assert.NoError(err)
	err = store.Commit(recoveryData)
	assert.NoError(err)

	// save more data to store
	err = store.BeginTransaction()
	assert.NoError(err)
	err = store.Put("another:input", testData2)
	assert.NoError(err)

	// rollback and verify only testData1 exists
	store.Rollback()
	val, err := store.Get("test:input")
	assert.NoError(err)
	assert.Equal(testData1, val)
	_, err = store.Get("another:input")
	assert.Error(err)

	// save something new
	err = store.BeginTransaction()
	assert.NoError(err)
	err = store.Put("last:input", testData3)
	assert.NoError(err)
	err = store.Commit(recoveryData)
	assert.NoError(err)

	// verify values
	val, err = store.Get("test:input")
	assert.NoError(err)
	assert.Equal(testData1, val)
	val, err = store.Get("last:input")
	assert.NoError(err)
	assert.Equal(testData3, val)
	_, err = store.Get("another:input")
	assert.Error(err)

}
