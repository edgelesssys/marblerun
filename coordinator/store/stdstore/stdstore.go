// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package stdstore

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/store"
)

// StdStore is the standard implementation of the Store interface.
type StdStore struct {
	data         map[string][]byte
	mux, txmux   sync.Mutex
	sealer       seal.Sealer
	recoveryData []byte
	recoveryMode bool
}

// New creates and initializes a new StdStore object.
func New(sealer seal.Sealer) *StdStore {
	s := &StdStore{
		data:   make(map[string][]byte),
		sealer: sealer,
	}

	return s
}

// Get retrieves a value from StdStore by Type and Name.
func (s *StdStore) Get(request string) ([]byte, error) {
	s.mux.Lock()
	value, ok := s.data[request]
	s.mux.Unlock()

	if ok {
		return value, nil
	}
	return nil, store.ErrValueUnset
}

// Put saves a value in StdStore by Type and Name.
func (s *StdStore) Put(request string, requestData []byte) error {
	tx, err := s.beginTransaction()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := tx.Put(request, requestData); err != nil {
		return err
	}
	return tx.Commit(context.Background())
}

// Delete removes a value from StdStore.
func (s *StdStore) Delete(request string) error {
	tx, err := s.beginTransaction()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := tx.Delete(request); err != nil {
		return err
	}
	return tx.Commit(context.Background())
}

// Iterator returns an iterator for keys saved in StdStore with a given prefix.
// For an empty prefix this is an iterator for all keys in StdStore.
func (s *StdStore) Iterator(prefix string) (store.Iterator, error) {
	keys := make([]string, 0)
	for k := range s.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}

	return &StdIterator{0, keys}, nil
}

// BeginTransaction starts a new transaction.
func (s *StdStore) BeginTransaction(_ context.Context) (store.Transaction, error) {
	return s.beginTransaction()
}

// LoadState loads sealed data into StdStore's data.
func (s *StdStore) LoadState() ([]byte, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	encodedRecoveryData, stateRaw, err := s.sealer.Unseal()
	if err != nil {
		s.recoveryMode = true
		return encodedRecoveryData, err
	}
	if len(stateRaw) == 0 {
		return encodedRecoveryData, nil
	}

	// load state
	var loadedData map[string][]byte
	if err := json.Unmarshal(stateRaw, &loadedData); err != nil {
		return encodedRecoveryData, err
	}

	s.data = loadedData
	return encodedRecoveryData, nil
}

// SetRecoveryData sets the recovery data that is added to the sealed data.
func (s *StdStore) SetRecoveryData(recoveryData []byte) {
	s.recoveryData = recoveryData
	s.recoveryMode = false
}

// SetEncryptionKey sets the encryption key for sealing and unsealing.
func (s *StdStore) SetEncryptionKey(encryptionKey []byte) error {
	return s.sealer.SetEncryptionKey(encryptionKey)
}

func (s *StdStore) beginTransaction() (*StdTransaction, error) {
	tx := StdTransaction{store: s, data: map[string][]byte{}}
	s.txmux.Lock()

	s.mux.Lock()
	for k, v := range s.data {
		tx.data[k] = v
	}
	s.mux.Unlock()

	return &tx, nil
}

func (s *StdStore) commit(data map[string][]byte) error {
	dataRaw, err := json.Marshal(data)
	if err != nil {
		return err
	}

	if !s.recoveryMode {
		if err := s.sealer.Seal(s.recoveryData, dataRaw); err != nil {
			return err
		}
	}

	s.mux.Lock()
	s.data = data
	s.mux.Unlock()

	s.txmux.Unlock()

	return nil
}

// StdTransaction is a transaction for StdStore.
type StdTransaction struct {
	store *StdStore
	data  map[string][]byte
}

// Get retrieves a value.
func (t *StdTransaction) Get(request string) ([]byte, error) {
	if value, ok := t.data[request]; ok {
		return value, nil
	}
	return nil, store.ErrValueUnset
}

// Put saves a value.
func (t *StdTransaction) Put(request string, requestData []byte) error {
	t.data[request] = requestData
	return nil
}

// Delete removes a value.
func (t *StdTransaction) Delete(request string) error {
	delete(t.data, request)
	return nil
}

// Iterator returns an iterator for all keys in the transaction with a given prefix.
func (t *StdTransaction) Iterator(prefix string) (store.Iterator, error) {
	keys := make([]string, 0)
	for k := range t.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}

	return &StdIterator{0, keys}, nil
}

// Commit ends a transaction and persists the changes.
func (t *StdTransaction) Commit(_ context.Context) error {
	if err := t.store.commit(t.data); err != nil {
		return err
	}
	t.store = nil
	return nil
}

// Rollback aborts a transaction.
func (t *StdTransaction) Rollback() {
	if t.store != nil {
		t.store.txmux.Unlock()
	}
}

// StdIterator is the standard Iterator implementation.
type StdIterator struct {
	idx  int
	keys []string
}

// GetNext implements the Iterator interface.
func (i *StdIterator) GetNext() (string, error) {
	if i.idx >= len(i.keys) {
		return "", fmt.Errorf("index out of range [%d] with length %d", i.idx, len(i.keys))
	}
	val := i.keys[i.idx]
	i.idx++
	return val, nil
}

// HasNext implements the Iterator interface.
func (i *StdIterator) HasNext() bool {
	return i.idx < len(i.keys)
}
