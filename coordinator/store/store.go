// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"errors"
)

// Store is the interface for persistence.
type Store interface {
	// BeginTransaction starts a new transaction.
	BeginTransaction(context.Context) (Transaction, error)
	// SetEncryptionKey sets the encryption key for the store.
	SetEncryptionKey([]byte) error
	// SetRecoveryData sets recovery data for the store.
	SetRecoveryData([]byte)
	// LoadState loads the sealed state of a store.
	LoadState() ([]byte, error)
}

// Transaction is a Store transaction.
type Transaction interface {
	// Get returns a value from store by key
	Get(string) ([]byte, error)
	// Put saves a value to store by key
	Put(string, []byte) error
	// Delete removes a value from store by key
	Delete(string) error
	// Iterator returns an Iterator for a given prefix
	Iterator(string) (Iterator, error)
	// Commit ends a transaction and persists the changes
	Commit(context.Context) error
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

// ErrValueUnset is returned when a requested value is not set in the store.
var ErrValueUnset = errors.New("requested value not set")
