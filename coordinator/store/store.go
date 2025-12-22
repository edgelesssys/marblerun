/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package store

import (
	"context"
	"errors"

	"github.com/edgelesssys/marblerun/coordinator/seal"
)

// Store is the interface for persistence.
type Store interface {
	// BeginTransaction starts a new transaction.
	BeginTransaction(context.Context) (Transaction, error)
	// SetEncryptionKey sets the encryption key for the store.
	SetEncryptionKey([]byte, seal.Mode)
	// ResetEncryptionKey resets the encryption key for the store.
	ResetEncryptionKey()
	// SealEncryptionKey seals the encryption key for the store.
	SealEncryptionKey(additionalData []byte) error
	// SetRecoveryData sets recovery data for the store.
	SetRecoveryData([]byte)
	// ResetRecoveryData resets the recovery data for the store.
	ResetRecoveryData()
	// LoadState loads the sealed state of a store.
	LoadState() (recoveryData, sealedData []byte, err error)
	// BeginReadTransaction loads the store from a sealed state without committing any data to it,
	// or modifying the underlying store in any way.
	BeginReadTransaction(context.Context, []byte) (ReadTransaction, error)
	// GetCiphertext gets the sealed data from the backend.
	GetCiphertext() ([]byte, error)
	// TestKey tests if the given key can be used to decrypt the given ciphertext.
	TestKey(key, ciphertext []byte) bool
	// PersistRecoveryData persists the given recovery data if it got lost.
	PersistRecoveryData(recoveryData []byte) error
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

// ReadTransaction is a read-only transaction on a [Store].
// While data can be written to the transaction, it cannot be committed to the [Store].
type ReadTransaction interface {
	// Get returns a value from store by key
	Get(string) ([]byte, error)
	// Put saves a value to store by key
	Put(string, []byte) error
	// Delete removes a value from store by key
	Delete(string) error
	// Iterator returns an Iterator for a given prefix
	Iterator(string) (Iterator, error)
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
