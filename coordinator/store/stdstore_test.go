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
)

func TestStdStore(t *testing.T) {
	assert := assert.New(t)

	store := NewStdStore(&seal.MockSealer{})
	_, err := store.LoadState()
	assert.NoError(err)

	testData1 := []byte("test data")
	testData2 := []byte("more test data")

	// request unset value
	_, err = store.Get("test:input")
	assert.Error(err)

	// test Put method
	tx, err := store.BeginTransaction()
	assert.NoError(err)
	assert.NoError(tx.Put("test:input", testData1))
	assert.NoError(tx.Put("another:input", testData2))
	assert.NoError(tx.Commit())

	// make sure values have been set
	val, err := store.Get("test:input")
	assert.NoError(err)
	assert.Equal(testData1, val)
	val, err = store.Get("another:input")
	assert.NoError(err)
	assert.Equal(testData2, val)

	_, err = store.Get("invalid:key")
	assert.Error(err)
	assert.True(IsStoreValueUnsetError(err))
}

func TestStdIterator(t *testing.T) {
	assert := assert.New(t)

	sealer := &seal.MockSealer{}
	store := NewStdStore(sealer)
	store.data = map[string][]byte{
		"test:1":    {0x00, 0x11},
		"test:2":    {0x00, 0x11},
		"test:3":    {0x00, 0x11},
		"value:1":   {0x00, 0x11},
		"something": {0x00},
	}

	iter, err := store.Iterator("test")
	assert.NoError(err)
	idx := 0
	for iter.HasNext() {
		idx++
		val, err := iter.GetNext()
		assert.NoError(err)
		assert.Contains(val, "test:")
	}
	assert.EqualValues(3, idx)

	iter, err = store.Iterator("value")
	assert.NoError(err)
	idx = 0
	for iter.HasNext() {
		idx++
		val, err := iter.GetNext()
		assert.NoError(err)
		assert.Contains(val, "value:")
	}
	assert.EqualValues(1, idx)

	iter, err = store.Iterator("")
	assert.NoError(err)
	idx = 0
	for iter.HasNext() {
		idx++
		_, err = iter.GetNext()
		assert.NoError(err)
	}
	assert.EqualValues(5, idx)

	iter, err = store.Iterator("empty")
	assert.NoError(err)
	assert.False(iter.HasNext())

	_, err = iter.GetNext()
	assert.Error(err)
}

func TestStdStoreSealing(t *testing.T) {
	assert := assert.New(t)

	sealer := &seal.MockSealer{}
	store := NewStdStore(sealer)
	_, err := store.LoadState()
	assert.NoError(err)

	testData1 := []byte("test data")
	assert.NoError(store.Put("test:input", testData1))

	// Check sealing with a new store initialized with the sealed state
	store2 := NewStdStore(sealer)
	_, err = store2.LoadState()
	assert.NoError(err)
	val, err := store2.Get("test:input")
	assert.NoError(err)
	assert.Equal(testData1, val)
}

func TestStdStoreRollback(t *testing.T) {
	assert := assert.New(t)

	store := NewStdStore(&seal.MockSealer{})
	_, err := store.LoadState()
	assert.NoError(err)

	testData1 := []byte("test data")
	testData2 := []byte("more test data")
	testData3 := []byte("and even more data")

	// save data to store and seal
	tx, err := store.BeginTransaction()
	assert.NoError(err)
	assert.NoError(tx.Put("test:input", testData1))
	assert.NoError(tx.Commit())

	// save more data to store
	tx, err = store.BeginTransaction()
	assert.NoError(err)
	assert.NoError(tx.Put("another:input", testData2))

	// rollback and verify only testData1 exists
	tx.Rollback()
	val, err := store.Get("test:input")
	assert.NoError(err)
	assert.Equal(testData1, val)
	_, err = store.Get("another:input")
	assert.Error(err)

	// save something new
	tx, err = store.BeginTransaction()
	assert.NoError(err)
	assert.NoError(tx.Put("last:input", testData3))
	assert.NoError(tx.Commit())

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
