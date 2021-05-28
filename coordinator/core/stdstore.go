// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"encoding/json"
	"fmt"
	"sync"

	"go.uber.org/zap"
)

// storeValueUnset is an error raised by unset values in the store
type storeValueUnset struct {
	requestedValue string
}

func (s *storeValueUnset) Error() string {
	return fmt.Sprintf("requested value not set: %s", s.requestedValue)
}

func isStoreValueUnsetError(err error) bool {
	_, ok := err.(*storeValueUnset)
	return ok
}

// StdStore is the standard implementation of the Store interface
type StdStore struct {
	data      map[string][]byte
	mux       sync.Mutex
	sealer    Sealer
	zaplogger *zap.Logger
}

// NewStdStore creates and initialises a new StdStore object
func NewStdStore(sealer Sealer, zaplogger *zap.Logger) Store {
	s := &StdStore{
		data:      make(map[string][]byte),
		sealer:    sealer,
		zaplogger: zaplogger,
	}

	return s
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

// LoadState loads sealed data into StdStore's data
func (s *StdStore) LoadState() ([]byte, error) {
	s.mux.Lock()
	defer s.mux.Unlock()
	encodedRecoveryData, stateRaw, err := s.sealer.Unseal()

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

// Put saves a value in StdStore by Type and Name
func (s *StdStore) Put(request string, requestData []byte) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	s.data[request] = requestData

	return nil
}

// SealState seals the state of StdStore using its sealer
func (s *StdStore) SealState(recoveryData []byte) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	dataRaw, err := json.Marshal(s.data)
	if err != nil {
		return err
	}

	return s.sealer.Seal(recoveryData, dataRaw)
}

// SetEncryptionKey sets the encryption key of the stores sealer
func (s *StdStore) SetEncryptionKey(encryptionKey []byte) error {
	return s.sealer.SetEncryptionKey(encryptionKey)
}
