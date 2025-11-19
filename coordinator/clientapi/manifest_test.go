/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package clientapi

import (
	"errors"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/store/distributed/wrapper"
	"github.com/stretchr/testify/assert"
)

func TestUpdateManifestEntries(t *testing.T) {
	someErr := errors.New("failed")
	testCases := map[string]struct {
		iterGetter  *stubIteratorGetter
		newEntries  map[string]testEntry
		store       map[string]testEntry
		wantDeleted []string
		wantAdded   []string
		deleteErr   error
		getErr      error
		putErr      error
		wantErr     bool
	}{
		"empty": {
			iterGetter: &stubIteratorGetter{
				iterator: &stubIterator{},
			},
			newEntries:  map[string]testEntry{},
			store:       map[string]testEntry{},
			wantDeleted: []string{},
			wantAdded:   []string{},
		},
		"add": {
			iterGetter: &stubIteratorGetter{
				iterator: &stubIterator{},
			},
			newEntries: map[string]testEntry{
				"test": "test",
			},
			store:       map[string]testEntry{},
			wantDeleted: []string{},
			wantAdded:   []string{"test"},
		},
		"delete": {
			iterGetter: &stubIteratorGetter{
				iterator: &stubIterator{
					keys: []string{"test"},
				},
			},
			newEntries:  map[string]testEntry{},
			store:       map[string]testEntry{"test": "test"},
			wantDeleted: []string{"test"},
			wantAdded:   []string{},
		},
		"add and delete": {
			iterGetter: &stubIteratorGetter{
				iterator: &stubIterator{
					keys: []string{"test2"},
				},
			},
			newEntries: map[string]testEntry{
				"test": "test",
			},
			store:       map[string]testEntry{"test2": "test2"},
			wantDeleted: []string{"test2"},
			wantAdded:   []string{"test"},
		},
		"add and delete with error": {
			iterGetter: &stubIteratorGetter{
				iterator: &stubIterator{
					keys: []string{"test2"},
				},
			},
			newEntries: map[string]testEntry{
				"test": "test",
			},
			store:     map[string]testEntry{"test2": "test2"},
			deleteErr: someErr,
			wantErr:   true,
		},
		"double entry uses old entry": {
			iterGetter: &stubIteratorGetter{
				iterator: &stubIterator{
					keys: []string{"test"},
				},
			},
			newEntries: map[string]testEntry{
				"test2": "test2",
				"test":  "test",
			},
			store: map[string]testEntry{
				"test": "test",
			},
			wantDeleted: []string{},
			wantAdded:   []string{"test2"},
		},
		"put fails": {
			iterGetter: &stubIteratorGetter{
				iterator: &stubIterator{},
			},
			newEntries: map[string]testEntry{
				"test": "test",
			},
			store:   map[string]testEntry{},
			putErr:  someErr,
			wantErr: true,
		},
		"delete fails": {
			iterGetter: &stubIteratorGetter{
				iterator: &stubIterator{
					keys: []string{"test"},
				},
			},
			newEntries: map[string]testEntry{},
			store:      map[string]testEntry{"test": "test"},
			deleteErr:  someErr,
			wantErr:    true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			added, deleted := []string{}, []string{}

			get := func(key string) (testEntry, error) {
				return tc.store[key], tc.getErr
			}
			put := func(key string, _ testEntry) error {
				added = append(added, key)
				return tc.putErr
			}
			del := func(key string) error {
				deleted = append(deleted, key)
				return tc.deleteErr
			}

			err := updateManifestEntries(wrapper.New(tc.iterGetter), "test", tc.newEntries, get, put, del)
			if tc.wantErr {
				assert.Error(err)
				return
			}

			assert.NoError(err)
			assert.ElementsMatch(tc.wantAdded, added, "Added entries don't match")
			assert.ElementsMatch(tc.wantDeleted, deleted, "Deleted entries don't match")
		})
	}
}

type testEntry string

func (e testEntry) Equal(other testEntry) bool {
	return e == other
}

func TestGetExistingEntries(t *testing.T) {
	someErr := errors.New("failed")
	testCases := map[string]struct {
		iterGetter *stubIteratorGetter
		store      map[string]any
		want       map[string]any
		getErr     error
		wantErr    bool
	}{
		"empty": {
			iterGetter: &stubIteratorGetter{
				iterator: &stubIterator{},
			},
			store: map[string]any{},
			want:  map[string]any{},
		},
		"single": {
			iterGetter: &stubIteratorGetter{
				iterator: &stubIterator{
					keys: []string{"foo"},
				},
			},
			store: map[string]any{
				"foo": 1,
			},
			want: map[string]any{
				"foo": 1,
			},
		},
		"multiple": {
			iterGetter: &stubIteratorGetter{
				iterator: &stubIterator{
					keys: []string{"foo", "bar"},
				},
			},
			store: map[string]any{
				"foo": 1,
				"bar": 2,
			},
			want: map[string]any{
				"foo": 1,
				"bar": 2,
			},
		},
		"GetIterator fails": {
			iterGetter: &stubIteratorGetter{
				getIteratorErr: someErr,
			},
			store: map[string]any{
				"foo": 1,
			},
			wantErr: true,
		},
		"GetNext fails": {
			iterGetter: &stubIteratorGetter{
				iterator: &stubIterator{
					keys:       []string{"foo"},
					getNextErr: someErr,
				},
			},
			store: map[string]any{
				"foo": 1,
			},
			wantErr: true,
		},
		"get fails": {
			iterGetter: &stubIteratorGetter{
				iterator: &stubIterator{
					keys: []string{"foo"},
				},
			},
			store: map[string]any{
				"foo": 1,
			},
			getErr:  someErr,
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			get := func(key string) (any, error) {
				if tc.getErr != nil {
					return nil, tc.getErr
				}
				return tc.store[key], nil
			}

			existing, err := getExistingEntries(wrapper.New(tc.iterGetter), "test", get)
			if tc.wantErr {
				assert.Error(err)
				return
			}

			assert.NoError(err)
			assert.Equal(tc.want, existing)
		})
	}
}

func TestCompareEntries(t *testing.T) {
	testCases := map[string]struct {
		old, new    map[string]any
		wantAdded   []string
		wantRemoved []string
		wantEqual   []string
	}{
		"empty": {
			old:         map[string]any{},
			new:         map[string]any{},
			wantAdded:   []string{},
			wantRemoved: []string{},
			wantEqual:   []string{},
		},
		"add": {
			old:         map[string]any{},
			new:         map[string]any{"a": 1},
			wantAdded:   []string{"a"},
			wantRemoved: []string{},
			wantEqual:   []string{},
		},
		"remove": {
			old:         map[string]any{"a": 1},
			new:         map[string]any{},
			wantAdded:   []string{},
			wantRemoved: []string{"a"},
			wantEqual:   []string{},
		},
		"add and remove": {
			old:         map[string]any{"a": 1},
			new:         map[string]any{"b": 2},
			wantAdded:   []string{"b"},
			wantRemoved: []string{"a"},
			wantEqual:   []string{},
		},
		"add and remove with equal": {
			old:         map[string]any{"a": 1, "b": 2},
			new:         map[string]any{"b": 2, "c": 3},
			wantAdded:   []string{"c"},
			wantRemoved: []string{"a"},
			wantEqual:   []string{"b"},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			added, removed, equal := compareKeys(tc.old, tc.new)
			assert.ElementsMatch(tc.wantAdded, added)
			assert.ElementsMatch(tc.wantRemoved, removed)
			assert.ElementsMatch(tc.wantEqual, equal)
		})
	}
}
