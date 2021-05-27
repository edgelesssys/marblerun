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

	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"go.uber.org/zap"
)

// storeValueUnset is an error raised by unset values in the store
type storeValueUnset struct {
	requestedValue string
}

func (s *storeValueUnset) Error() string {
	return fmt.Sprintf("requested value %s not set", s.requestedValue)
}

// StdStore is the standard implementation of the Store interface
type StdStore struct {
	coreData  map[string][]byte
	mux       sync.Mutex
	sealer    Sealer
	recovery  recovery.Recovery
	zaplogger *zap.Logger
}

// NewStdStore creates and initialises a new StdStore object
func NewStdStore(sealer Sealer, recovery recovery.Recovery, zaplogger *zap.Logger) Store {
	s := &StdStore{
		coreData:  make(map[string][]byte),
		sealer:    sealer,
		recovery:  recovery,
		zaplogger: zaplogger,
	}

	return s
}

// Get retrieves a value from StdStore by Type and Name
func (s *StdStore) Get(request string) ([]byte, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	value, ok := s.coreData[request]
	if !ok {
		return nil, &storeValueUnset{requestedValue: request}
	}
	return value, nil
}

// LoadState loads sealed data into StdStore's coreData
func (s *StdStore) LoadState() error {
	s.mux.Lock()
	defer s.mux.Unlock()
	encodedRecoveryData, stateRaw, unsealErr := s.sealer.Unseal()

	// Retrieve and set recovery data from state
	err := s.recovery.SetRecoveryData(encodedRecoveryData)
	if err != nil {
		s.zaplogger.Error("Could not retrieve recovery data from state. Recovery will be unavailable", zap.Error(err))
	}

	if unsealErr != nil {
		return unsealErr
	}
	if len(stateRaw) == 0 {
		return nil
	}

	// load state
	s.zaplogger.Info("applying sealed state")
	var loadedCoreData map[string][]byte
	if err := json.Unmarshal(stateRaw, &loadedCoreData); err != nil {
		return err
	}

	s.coreData = loadedCoreData
	return nil
}

// Put saves a value in StdStore by Type and Name
func (s *StdStore) Put(request string, requestData []byte) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	s.coreData[request] = requestData

	return nil
}

// SealState seals the state of StdStore using its sealer
func (s *StdStore) SealState() error {
	s.mux.Lock()
	defer s.mux.Unlock()

	recoveryData, err := s.recovery.GetRecoveryData()
	if err != nil {
		return err
	}

	dataRaw, err := json.Marshal(s.coreData)
	if err != nil {
		return err
	}

	return s.sealer.Seal(recoveryData, dataRaw)
}
