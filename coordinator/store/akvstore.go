// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
)

// AKVStore is a store using Azure Key Vault as a storage backend
type AKVStore struct {
	akvClient  keyvault.BaseClient
	baseUrl    string
	mux, txmux sync.Mutex
}

func NewAKVStore(vaultUrl string) (*AKVStore, error) {

	client := keyvault.New()
	var err error
	client.Authorizer, err = auth.NewAuthorizerFromEnvironment()
	if err != nil {
		return nil, err
	}
	s := &AKVStore{
		akvClient: client,
		baseUrl:   vaultUrl,
	}
	return s, nil
}

// Get retrieves a value from the keyvault
func (s *AKVStore) Get(request string) ([]byte, error) {
	// request a value using s.akvClient.GetSecret
	return nil, nil
}

// Put saves a values to the keyvault
func (s *AKVStore) Put(request string, requestData []byte) error {
	// save a value using s.akvClient.SetSecret
	return nil
}

// Iterator returns an iterator for values saved in the keyvault
func (s *AKVStore) Iterator(prefix string) (Iterator, error) {
	// create an Iterator
	// possible solution: GetSecrets, GetSecretsComplete
	// the later returns a custom iterator -> create a wrapper to use for marblerun
	return nil, nil
}

// BeginTransaction starts a new transaction for the keyvault
func (s *AKVStore) BeginTransaction() (Transaction, error) {
	tx := &akvTransaction{store: s, data: map[string]byte{}}
	s.txmux.Lock()
	return tx, nil
}

// LoadState keeps compatibility with other storage backends
func (s *AKVStore) LoadState() ([]byte, error) {
	// maybe change the current code to instead accept a "Initialize" method?
	return nil, nil
}

type akvTransaction struct {
	store *AKVStore
	data  map[string]byte //maybe use a different structure here? Potential option to make use of GetSecretPreparer
}

func (t *akvTransaction) Get(request string) ([]byte, error) {
	// return a value from the transaction
	return nil, nil
}

func (t *akvTransaction) Put(request string, requestData []byte) error {
	// add a value to the transaction
	return nil
}

func (t *akvTransaction) Iterator(prefix string) (Iterator, error) {
	keys := make([]string, 0)
	for k := range t.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}

	return &StdIterator{0, keys}, nil
}

func (t *akvTransaction) Commit() error {
	// save all values from the transaction to the keyvault
	return nil
}

func (t *akvTransaction) Rollback() {
	if t.store != nil {
		t.store.txmux.Unlock()
	}
}
