// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import "fmt"

// Store is the interface for state transactions and persistance
type Store interface {
	// Get returns a value from store by key
	Get(string) ([]byte, error)
	// Put saves a value to store by key
	Put(string, []byte) error
	// SealState encrypts and persists the state of the store
	SealState(recoveryData []byte) error
	// LoadState loads the encrypted state of the store
	LoadState() ([]byte, error)
	// SetEncryptionKey sets the key used by SealState
	SetEncryptionKey([]byte) error
}

// storeValueUnset is an error raised by unset values in the store
type storeValueUnset struct {
	requestedValue string
}

// Error implements the Error interface
func (s *storeValueUnset) Error() string {
	return fmt.Sprintf("requested value not set: %s", s.requestedValue)
}

// IsStoreValueUnsetError returns true if an error is of type storeValueUnset
func IsStoreValueUnsetError(err error) bool {
	_, ok := err.(*storeValueUnset)
	return ok
}
