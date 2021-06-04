// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/edgelesssys/marblerun/coordinator/seal"
	"go.uber.org/zap"
)

type stdStoreState int

const (
	stateUninitialized stdStoreState = iota
	stateIdle
	stateAcceptingData
)

// StdStore is the standard implementation of the Store interface
type StdStore struct {
	data      map[string][]byte
	oldData   map[string][]byte
	mux       sync.Mutex
	sealer    seal.Sealer
	state     stdStoreState
	zaplogger *zap.Logger
}

// NewStdStore creates and initialises a new StdStore object
func NewStdStore(sealer seal.Sealer, zaplogger *zap.Logger) Store {
	s := &StdStore{
		data:      make(map[string][]byte),
		oldData:   make(map[string][]byte),
		sealer:    sealer,
		state:     stateUninitialized,
		zaplogger: zaplogger,
	}

	return s
}

// requireState ensures a method is only executed in the correc state
func (s *StdStore) requireState(state stdStoreState) error {
	s.mux.Lock()
	if s.state != state {
		return errors.New("store is not in required state")
	}
	return nil
}

// Get retrieves a value from StdStore by Type and Name
func (s *StdStore) Get(request string) ([]byte, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	value, ok := s.data[request]
	if !ok {
		return nil, &storeValueUnset{requestedValue: request}
	}
	return value, nil
}

// Put saves a value in StdStore by Type and Name
func (s *StdStore) Put(request string, requestData []byte) error {
	defer s.mux.Unlock()
	if err := s.requireState(stateAcceptingData); err != nil {
		return err
	}

	s.data[request] = requestData

	return nil
}

// BeginTransaction starts a new transaction by making a copy of the current data
func (s *StdStore) BeginTransaction() error {
	defer s.mux.Unlock()
	if err := s.requireState(stateIdle); err != nil {
		return err
	}

	s.state = stateAcceptingData
	// copy current state as backup
	s.oldData = make(map[string][]byte)
	for k, v := range s.data {
		s.oldData[k] = v
	}
	return nil
}

// Commit persists and seals data of StdStore
func (s *StdStore) Commit(recoveryData []byte) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	dataRaw, err := json.Marshal(s.data)
	if err != nil {
		return err
	}

	s.state = stateIdle
	return s.sealer.Seal(recoveryData, dataRaw)
}

// LoadState loads sealed data into StdStore's data
func (s *StdStore) LoadState() ([]byte, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	encodedRecoveryData, stateRaw, err := s.sealer.Unseal()
	s.state = stateIdle
	if err != nil {
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

// Rollback reverts the store to the previous state
func (s *StdStore) Rollback() {
	if s.oldData == nil {
		s.zaplogger.Panic("no state to rollback to")
	}
	s.data = s.oldData
	s.state = stateIdle
}

// SetEncryptionKey sets the encryption key of the stores sealer
func (s *StdStore) SetEncryptionKey(encryptionKey []byte) error {
	return s.sealer.SetEncryptionKey(encryptionKey)
}
