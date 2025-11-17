/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package transaction

import (
	"strings"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
	"go.uber.org/zap/zaptest"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestGet(t *testing.T) {
	testCases := map[string]struct {
		request string
		data    map[string][]byte
		want    []byte
		wantErr bool
	}{
		"get existing value": {
			request: "key",
			data: map[string][]byte{
				"key": []byte("value"),
			},
			want: []byte("value"),
		},
		"get non-existing value": {
			request: "key",
			data:    map[string][]byte{},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			tx := New(nil, tc.data, nil, zaptest.NewLogger(t))
			got, err := tx.Get(tc.request)
			if tc.wantErr {
				assert.Error(err)
				if _, ok := tc.data[tc.request]; !ok {
					assert.ErrorIs(err, store.ErrValueUnset)
				}
				return
			}
			assert.NoError(err)
			assert.Equal(tc.want, got)
		})
	}
}

func TestPut(t *testing.T) {
	assert := assert.New(t)

	data := map[string][]byte{}
	key := "key"
	value := []byte("value")

	tx := New(nil, data, nil, zaptest.NewLogger(t))

	err := tx.Put(key, value)
	assert.NoError(err)

	got, ok := data[key]
	assert.True(ok)
	assert.Equal(value, got)
}

func TestDelete(t *testing.T) {
	assert := assert.New(t)

	key := "key"
	value := []byte("value")

	data := map[string][]byte{
		key: value,
	}

	tx := New(nil, data, nil, zaptest.NewLogger(t))

	err := tx.Delete(key)
	assert.NoError(err)
	_, ok := data[key]
	assert.False(ok)
}

func TestIterator(t *testing.T) {
	data := func() map[string][]byte {
		return map[string][]byte{
			"test:1":    {0x00, 0x11},
			"test:2":    {0x00, 0x11},
			"test:3":    {0x00, 0x11},
			"value:1":   {0x00, 0x11},
			"something": {0x00},
		}
	}

	testCases := map[string]struct {
		data       map[string][]byte
		prefix     string
		wantValues int
	}{
		"no prefix - all values": {
			data:       data(),
			prefix:     "",
			wantValues: 5,
		},
		"prefix test": {
			data:       data(),
			prefix:     "test",
			wantValues: 3,
		},
		"prefix value": {
			data:       data(),
			prefix:     "value",
			wantValues: 1,
		},
		"prefix non-existing": {
			data:       data(),
			prefix:     "non-existing",
			wantValues: 0,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			tx := New(nil, tc.data, nil, zaptest.NewLogger(t))

			iter, err := tx.Iterator(tc.prefix)
			assert.NoError(err)
			idx := 0
			for iter.HasNext() {
				idx++
				val, err := iter.GetNext()
				assert.NoError(err)
				assert.True(strings.HasPrefix(val, tc.prefix))
			}
			assert.EqualValues(tc.wantValues, idx)
		})
	}
}
