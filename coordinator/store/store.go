// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import "fmt"

// Store is the interface for persistence.
type Store interface {
	// BeginTransaction starts a new transaction
	BeginTransaction() (Transaction, error)
	// Get returns a value from store by key
	Get(string) ([]byte, error)
	// Put saves a value to store by key
	Put(string, []byte) error
	// Iterator returns an Iterator for a given prefix
	Iterator(string) (Iterator, error)
}

// Transaction is a Store transaction.
type Transaction interface {
	// Get returns a value from store by key
	Get(string) ([]byte, error)
	// Put saves a value to store by key
	Put(string, []byte) error
	// Iterator returns an Iterator for a given prefix
	Iterator(string) (Iterator, error)
	// Commit ends a transaction and persists the changes
	Commit() error
	// Rollback aborts a transaction. Noop if already committed.
	Rollback()
}

// Iterator is an iterator for the store.
type Iterator interface {
	// Returns the next element of the iterator
	GetNext() (string, error)
	// HasNext returns true if there is at least one more item after the current position
	HasNext() bool
}

// storeValueUnset is an error raised by unset values in the store.
type storeValueUnset struct {
	requestedValue string
}

// Error implements the Error interface.
func (s *storeValueUnset) Error() string {
	return fmt.Sprintf("requested value not set: %s", s.requestedValue)
}

// IsStoreValueUnsetError returns true if an error is of type storeValueUnset.
func IsStoreValueUnsetError(err error) bool {
	_, ok := err.(*storeValueUnset)
	return ok
}
