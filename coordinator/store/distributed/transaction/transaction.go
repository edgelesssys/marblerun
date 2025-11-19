/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// Package transaction implements store transaction for distributed MarbleRun coordinators.
package transaction

import (
	"context"
	"fmt"
	"strings"

	"github.com/edgelesssys/marblerun/coordinator/store"
	"go.uber.org/zap"
)

// State holds the persistent state of a transaction.
// It holds the sealed data and key, as well as a reference to the underlying data type.
type State struct {
	SealedData []byte
	SealedKey  []byte
	StateRef   any
}

// Transaction is a transaction on a state.
type Transaction struct {
	committer committer

	state *State
	data  map[string][]byte
	log   *zap.Logger
}

// New creates and initializes a new transaction.
func New(committer committer, data map[string][]byte, state *State, log *zap.Logger) *Transaction {
	return &Transaction{
		committer: committer,
		state:     state,
		data:      data,
		log:       log,
	}
}

// Get retrieves a value.
func (t *Transaction) Get(request string) ([]byte, error) {
	t.log.Debug("Retrieving value from transaction", zap.String("request", request))
	if value, ok := t.data[request]; ok {
		return value, nil
	}
	return nil, store.ErrValueUnset
}

// Put saves a value.
func (t *Transaction) Put(request string, requestData []byte) error {
	t.log.Debug("Saving value to transaction", zap.String("request", request))
	t.data[request] = requestData
	return nil
}

// Delete removes a value.
func (t *Transaction) Delete(request string) error {
	t.log.Debug("Deleting value from transaction", zap.String("request", request))
	delete(t.data, request)
	return nil
}

// Iterator returns an iterator for all keys in the transaction with a given prefix.
func (t *Transaction) Iterator(prefix string) (store.Iterator, error) {
	t.log.Debug("Creating iterator for transaction", zap.String("prefix", prefix))
	keys := make([]string, 0)
	for k := range t.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}

	return &Iterator{0, keys}, nil
}

// Commit ends a transaction and persists the changes.
func (t *Transaction) Commit(ctx context.Context) error {
	t.log.Debug("Committing transaction")
	if err := t.committer.Commit(ctx, t.state, t.data); err != nil {
		return err
	}
	t.committer = nil
	return nil
}

// Rollback aborts a transaction.
func (t *Transaction) Rollback() {
	t.log.Debug("Rolling back transaction")
	if t.committer != nil {
		t.committer.UnlockTxMux()
	}
}

// Iterator iterates over keys.
type Iterator struct {
	idx  int
	keys []string
}

// GetNext returns the next key in the iterator's list.
func (i *Iterator) GetNext() (string, error) {
	if i.idx >= len(i.keys) {
		return "", fmt.Errorf("index out of range [%d] with length %d", i.idx, len(i.keys))
	}
	val := i.keys[i.idx]
	i.idx++
	return val, nil
}

// HasNext returns true if there are keys remaining in the iterator's list.
func (i *Iterator) HasNext() bool {
	return i.idx < len(i.keys)
}

type committer interface {
	Commit(ctx context.Context, state *State, data map[string][]byte) error
	UnlockTxMux()
}
