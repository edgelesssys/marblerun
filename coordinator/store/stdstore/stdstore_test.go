/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package stdstore

import (
	"context"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestStdStore(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()

	str := New(&seal.MockSealer{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
	_, _, err := str.LoadState()
	assert.NoError(err)

	testData1 := []byte("test data")
	testData2 := []byte("more test data")

	// request unset value
	_, err = str.Get("test:input")
	assert.Error(err)

	// test Put method
	tx, err := str.BeginTransaction(ctx)
	assert.NoError(err)
	assert.NoError(tx.Put("test:input", testData1))
	assert.NoError(tx.Put("another:input", testData2))
	assert.NoError(tx.Commit(ctx))

	// make sure values have been set
	val, err := str.Get("test:input")
	assert.NoError(err)
	assert.Equal(testData1, val)
	val, err = str.Get("another:input")
	assert.NoError(err)
	assert.Equal(testData2, val)

	_, err = str.Get("invalid:key")
	assert.Error(err)
	assert.ErrorIs(err, store.ErrValueUnset)
}

func TestStdIterator(t *testing.T) {
	assert := assert.New(t)

	sealer := &seal.MockSealer{}
	store := New(sealer, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
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
	testCases := map[string]struct {
		mode    seal.Mode
		wantErr bool
	}{
		"product key": {mode: seal.ModeProductKey},
		"unique key":  {mode: seal.ModeUniqueKey},
		"disabled":    {mode: seal.ModeDisabled, wantErr: true},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			fs := afero.NewMemMapFs()
			sealer := &seal.MockSealer{}

			store := New(sealer, fs, "", zaptest.NewLogger(t))
			_, _, err := store.LoadState()
			require.NoError(err)

			store.SetEncryptionKey(nil, tc.mode)

			testData1 := []byte("test data")
			require.NoError(store.Put("test:input", testData1))

			// Check sealing with a new store initialized with the sealed state
			store2 := New(sealer, fs, "", zaptest.NewLogger(t))
			_, _, err = store2.LoadState()
			require.NoError(err)
			val, err := store2.Get("test:input")

			if tc.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(testData1, val)
		})
	}
}

func TestStdStoreRollback(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()

	store := New(&seal.MockSealer{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))
	_, _, err := store.LoadState()
	assert.NoError(err)

	testData1 := []byte("test data")
	testData2 := []byte("more test data")
	testData3 := []byte("and even more data")

	// save data to store and seal
	tx, err := store.BeginTransaction(ctx)
	assert.NoError(err)
	assert.NoError(tx.Put("test:input", testData1))
	assert.NoError(tx.Commit(ctx))

	// save more data to store
	tx, err = store.BeginTransaction(ctx)
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
	tx, err = store.BeginTransaction(ctx)
	assert.NoError(err)
	assert.NoError(tx.Put("last:input", testData3))
	assert.NoError(tx.Commit(ctx))

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

func TestStdStoreDelete(t *testing.T) {
	assert := assert.New(t)

	str := New(&seal.MockSealer{}, afero.NewMemMapFs(), "", zaptest.NewLogger(t))

	inputName := "test:input"
	inputData := []byte("test data")

	assert.NoError(str.Delete(inputName))

	assert.NoError(str.Put(inputName, inputData))
	out, err := str.Get("test:input")
	assert.NoError(err)
	assert.Equal(inputData, out)

	assert.NoError(str.Delete(inputName))
	_, err = str.Get(inputName)
	assert.Error(err)
	assert.ErrorIs(err, store.ErrValueUnset)
}
