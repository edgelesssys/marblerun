// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"encoding/base64"
	"net/http"
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
	ctx        context.Context
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
		ctx:       context.TODO(), // TODO: Find a proper context here
	}
	return s, nil
}

// Get retrieves a value from the keyvault
func (s *AKVStore) Get(request string) ([]byte, error) {
	s.mux.Lock()
	defer s.mux.Unlock()
	result, err := s.akvClient.GetSecret(s.ctx, s.baseUrl, request, "")
	if err != nil {
		return nil, err
	}

	return base64.RawStdEncoding.DecodeString(*result.Value)
}

// Put saves a values to the keyvault
func (s *AKVStore) Put(request string, requestData []byte) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	requestDataBase64 := base64.RawStdEncoding.EncodeToString(requestData)
	secretParameters := keyvault.SecretSetParameters{
		Value: &requestDataBase64,
	}
	_, err := s.akvClient.SetSecret(s.ctx, s.baseUrl, request, secretParameters)
	if err != nil {
		return err
	}

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
	tx := &akvTransaction{store: s, data: map[string]akvTransactionData{}}
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
	data  map[string]akvTransactionData //maybe use a different structure here? Potential option to make use of GetSecretPreparer
}

type akvTransactionData struct {
	data    []byte
	request *http.Request
}

func (t *akvTransaction) Get(request string) ([]byte, error) {
	if value, ok := t.data[request]; ok {
		return value.data, nil
	}
	return nil, &storeValueUnset{requestedValue: request}
}

func (t *akvTransaction) Put(request string, requestData []byte) error {
	requestDataBase64 := base64.RawStdEncoding.EncodeToString(requestData)
	secretParameters := keyvault.SecretSetParameters{
		Value: &requestDataBase64,
	}
	preparedRequest, err := t.store.akvClient.SetSecretPreparer(t.store.ctx, t.store.baseUrl, request, secretParameters)
	if err != nil {
		return err
	}

	singleTransaction := akvTransactionData{data: requestData, request: preparedRequest}
	t.data[request] = singleTransaction

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
	// TODO: Wrap this in a goroutine for parallelized setting?
	for _, value := range t.data {
		resp, err := t.store.akvClient.SetSecretSender(value.request)
		if err != nil {
			return err
		}
		_, err = t.store.akvClient.SetSecretResponder(resp)
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *akvTransaction) Rollback() {
	if t.store != nil {
		t.store.txmux.Unlock()
	}
}
