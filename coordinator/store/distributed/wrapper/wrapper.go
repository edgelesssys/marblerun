/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package wrapper

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/edgelesssys/marblerun/coordinator/multiupdate"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/store/request"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper"
)

// Wrapper is a wrapper that adds support for delete operations.
type Wrapper struct {
	wrapper.Wrapper
	store dataStore
}

// WrapTransaction initializes a transaction using the given handle,
// and returns a wrapper for the transaction, as well as rollback and commit functions.
func WrapTransaction(ctx context.Context, txHandle transactionHandle,
) (wrapper Wrapper, rollback func(), commit func(context.Context) error, err error) {
	tx, err := txHandle.BeginTransaction(ctx)
	if err != nil {
		return Wrapper{}, nil, nil, err
	}
	return New(tx), tx.Rollback, tx.Commit, nil
}

// New creates a new Wrapper.
func New(store dataStore) Wrapper {
	return Wrapper{
		Wrapper: wrapper.New(store),
		store:   store,
	}
}

// DeleteActivation deletes an activation from the store.
func (w Wrapper) DeleteActivation(marbleType string) error {
	return w.store.Delete(strings.Join([]string{request.Activations, marbleType}, ":"))
}

// DeleteCertificate deletes a certificate from the store.
func (w Wrapper) DeleteCertificate(certType string) error {
	return w.store.Delete(strings.Join([]string{request.Certificate, certType}, ":"))
}

// DeleteInfrastructure deletes an infrastructure from the store.
func (w Wrapper) DeleteInfrastructure(infraName string) error {
	return w.store.Delete(strings.Join([]string{request.Infrastructure, infraName}, ":"))
}

// DeleteMarble deletes a marble from the store.
func (w Wrapper) DeleteMarble(marbleType string) error {
	return w.store.Delete(strings.Join([]string{request.Marble, marbleType}, ":"))
}

// DeletePackage deletes a package from the store.
func (w Wrapper) DeletePackage(packageName string) error {
	return w.store.Delete(strings.Join([]string{request.Package, packageName}, ":"))
}

// DeleteSecret deletes a secret from the store.
func (w Wrapper) DeleteSecret(secretName string) error {
	return w.store.Delete(strings.Join([]string{request.Secret, secretName}, ":"))
}

// DeleteTLS deletes a TLS certificate from the store.
func (w Wrapper) DeleteTLS(tagName string) error {
	return w.store.Delete(strings.Join([]string{request.TLS, tagName}, ":"))
}

// DeleteUser deletes a user from the store.
func (w Wrapper) DeleteUser(username string) error {
	return w.store.Delete(strings.Join([]string{request.User, username}, ":"))
}

// DeletePendingUpdate deletes a pending update from the store.
func (w Wrapper) DeletePendingUpdate() error {
	return w.store.Delete(multiupdate.RequestPendingUpdate)
}

// GetPendingUpdate returns a pending update from the store.
func (w Wrapper) GetPendingUpdate() (*multiupdate.MultiPartyUpdate, error) {
	rawData, err := w.store.Get(multiupdate.RequestPendingUpdate)
	if err != nil {
		return nil, err
	}
	var update multiupdate.MultiPartyUpdate
	if err := json.Unmarshal(rawData, &update); err != nil {
		return nil, err
	}
	return &update, nil
}

// PutPendingUpdate saves a pending update to the store.
func (w Wrapper) PutPendingUpdate(update *multiupdate.MultiPartyUpdate) error {
	rawData, err := json.Marshal(update)
	if err != nil {
		return err
	}
	return w.store.Put(multiupdate.RequestPendingUpdate, rawData)
}

type dataStore interface {
	// Get returns a value from store by key
	Get(string) ([]byte, error)
	// Put saves a value to store by key
	Put(string, []byte) error
	// Delete removes a value from store by key
	Delete(string) error
	// Iterator returns an Iterator for a given prefix
	Iterator(string) (store.Iterator, error)
}

type transactionHandle interface {
	BeginTransaction(context.Context) (store.Transaction, error)
}
