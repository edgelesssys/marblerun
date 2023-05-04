// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package stdstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/spf13/afero"
)

const (
	// SealedDataFname is the file name in which the state is sealed on disk in seal_dir.
	SealedDataFname string = "sealed_data"

	// SealedKeyFname is the file name in which the key is sealed with the seal key on disk in seal_dir.
	SealedKeyFname string = "sealed_key"
)

// StdStore is the standard implementation of the Store interface.
type StdStore struct {
	data       map[string][]byte
	mux, txmux sync.Mutex
	sealer     seal.Sealer

	fs           afero.Afero
	recoveryData []byte
	recoveryMode bool
	sealDir      string
}

// New creates and initializes a new StdStore object.
func New(sealer seal.Sealer, fs afero.Fs, sealDir string) *StdStore {
	s := &StdStore{
		data:    make(map[string][]byte),
		sealer:  sealer,
		fs:      afero.Afero{Fs: fs},
		sealDir: sealDir,
	}

	return s
}

// Get retrieves a value from StdStore by Type and Name.
func (s *StdStore) Get(request string) ([]byte, error) {
	s.mux.Lock()
	value, ok := s.data[request]
	s.mux.Unlock()

	if ok {
		return value, nil
	}
	return nil, store.ErrValueUnset
}

// Put saves a value in StdStore by Type and Name.
func (s *StdStore) Put(request string, requestData []byte) error {
	tx := s.beginTransaction()
	defer tx.Rollback()
	if err := tx.Put(request, requestData); err != nil {
		return err
	}
	return tx.Commit(context.Background())
}

// Delete removes a value from StdStore.
func (s *StdStore) Delete(request string) error {
	tx := s.beginTransaction()
	defer tx.Rollback()
	if err := tx.Delete(request); err != nil {
		return err
	}
	return tx.Commit(context.Background())
}

// Iterator returns an iterator for keys saved in StdStore with a given prefix.
// For an empty prefix this is an iterator for all keys in StdStore.
func (s *StdStore) Iterator(prefix string) (store.Iterator, error) {
	keys := make([]string, 0)
	for k := range s.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}

	return &StdIterator{0, keys}, nil
}

// BeginTransaction starts a new transaction.
func (s *StdStore) BeginTransaction(_ context.Context) (store.Transaction, error) {
	return s.beginTransaction(), nil
}

// LoadState loads sealed data into StdStore's data.
func (s *StdStore) LoadState() ([]byte, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	// load from fs
	sealedData, err := s.fs.ReadFile(filepath.Join(s.sealDir, SealedDataFname))
	if errors.Is(err, afero.ErrFileNotFound) {
		// No sealed data found, back up any existing seal keys
		s.backupEncryptionKey()
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	encodedRecoveryData, stateRaw, err := s.sealer.Unseal(sealedData)
	if err != nil {
		if !errors.Is(err, seal.ErrMissingEncryptionKey) {
			s.recoveryMode = true
			return encodedRecoveryData, fmt.Errorf("unsealing state: %w", err)
		}
		// Try to unseal encryption key from disk using product key
		// And retry unsealing the sealed data
		if err := s.unsealEncryptionKey(); err != nil {
			s.recoveryMode = true
			return encodedRecoveryData, &seal.EncryptionKeyError{Err: err}
		}

		encodedRecoveryData, stateRaw, err = s.sealer.Unseal(sealedData)
		if err != nil {
			s.recoveryMode = true
			return encodedRecoveryData, fmt.Errorf("retry unsealing state with loaded key: %w", err)
		}
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

// SetRecoveryData sets the recovery data that is added to the sealed data.
func (s *StdStore) SetRecoveryData(recoveryData []byte) {
	s.recoveryData = recoveryData
	s.recoveryMode = false
}

// SetEncryptionKey sets the encryption key for sealing and unsealing.
func (s *StdStore) SetEncryptionKey(encryptionKey []byte) error {
	// If there already is an existing key file stored on disk, save it
	s.backupEncryptionKey()

	encryptedKey, err := s.sealer.SealEncryptionKey(encryptionKey)
	if err != nil {
		return fmt.Errorf("encrypting data key: %w", err)
	}

	// Write the sealed encryption key to disk
	if err = s.fs.WriteFile(filepath.Join(s.sealDir, SealedKeyFname), encryptedKey, 0o600); err != nil {
		return fmt.Errorf("writing encrypted key to disk: %w", err)
	}

	s.sealer.SetEncryptionKey(encryptionKey)

	return nil
}

func (s *StdStore) beginTransaction() *StdTransaction {
	tx := StdTransaction{store: s, data: map[string][]byte{}}
	s.txmux.Lock()

	s.mux.Lock()
	for k, v := range s.data {
		tx.data[k] = v
	}
	s.mux.Unlock()

	return &tx
}

// commit saves the store's data to disk.
func (s *StdStore) commit(data map[string][]byte) error {
	dataRaw, err := json.Marshal(data)
	if err != nil {
		return err
	}

	s.mux.Lock()
	defer s.mux.Unlock()
	if !s.recoveryMode {
		sealedData, err := s.sealer.Seal(s.recoveryData, dataRaw)
		if err != nil {
			if !errors.Is(err, seal.ErrMissingEncryptionKey) {
				return err
			}

			// No encryption key set
			// Load or generate new key, and retry sealing
			if err := s.unsealEncryptionKey(); err != nil {
				if !errors.Is(err, afero.ErrFileNotFound) {
					return err
				}

				// No encryption key on disk
				// Generate a new encryption key, and seal it with product key
				encryptionKey, err := seal.GenerateEncryptionKey()
				if err != nil {
					return err
				}
				if err := s.SetEncryptionKey(encryptionKey); err != nil {
					return err
				}
			}

			sealedData, err = s.sealer.Seal(s.recoveryData, dataRaw)
			if err != nil {
				return err
			}
		}

		if err := s.fs.WriteFile(filepath.Join(s.sealDir, SealedDataFname), sealedData, 0o600); err != nil {
			return err
		}
	}

	s.data = data
	s.txmux.Unlock()

	return nil
}

// unsealEncryptionKey sets the seal key for the store's sealer by loading the encrypted key from disk.
func (s *StdStore) unsealEncryptionKey() error {
	encryptedKey, err := s.fs.ReadFile(filepath.Join(s.sealDir, SealedKeyFname))
	if err != nil {
		return fmt.Errorf("reading encrypted key from disk: %w", err)
	}
	key, err := s.sealer.UnsealEncryptionKey(encryptedKey)
	if err != nil {
		return fmt.Errorf("decrypting data key: %w", err)
	}
	s.sealer.SetEncryptionKey(key)
	return nil
}

// backupEncryptionKey creates a backup of an existing seal key.
func (s *StdStore) backupEncryptionKey() {
	if sealedKeyData, err := s.fs.ReadFile(filepath.Join(s.sealDir, SealedKeyFname)); err == nil {
		t := time.Now()
		newFileName := filepath.Join(s.sealDir, SealedKeyFname) + "_" + t.Format("20060102150405") + ".bak"
		_ = s.fs.WriteFile(newFileName, sealedKeyData, 0o600)
	}
}

// StdTransaction is a transaction for StdStore.
type StdTransaction struct {
	store *StdStore
	data  map[string][]byte
}

// Get retrieves a value.
func (t *StdTransaction) Get(request string) ([]byte, error) {
	if value, ok := t.data[request]; ok {
		return value, nil
	}
	return nil, store.ErrValueUnset
}

// Put saves a value.
func (t *StdTransaction) Put(request string, requestData []byte) error {
	t.data[request] = requestData
	return nil
}

// Delete removes a value.
func (t *StdTransaction) Delete(request string) error {
	delete(t.data, request)
	return nil
}

// Iterator returns an iterator for all keys in the transaction with a given prefix.
func (t *StdTransaction) Iterator(prefix string) (store.Iterator, error) {
	keys := make([]string, 0)
	for k := range t.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}

	return &StdIterator{0, keys}, nil
}

// Commit ends a transaction and persists the changes.
func (t *StdTransaction) Commit(_ context.Context) error {
	if err := t.store.commit(t.data); err != nil {
		return err
	}
	t.store = nil
	return nil
}

// Rollback aborts a transaction.
func (t *StdTransaction) Rollback() {
	if t.store != nil {
		t.store.txmux.Unlock()
	}
}

// StdIterator is the standard Iterator implementation.
type StdIterator struct {
	idx  int
	keys []string
}

// GetNext implements the Iterator interface.
func (i *StdIterator) GetNext() (string, error) {
	if i.idx >= len(i.keys) {
		return "", fmt.Errorf("index out of range [%d] with length %d", i.idx, len(i.keys))
	}
	val := i.keys[i.idx]
	i.idx++
	return val, nil
}

// HasNext implements the Iterator interface.
func (i *StdIterator) HasNext() bool {
	return i.idx < len(i.keys)
}
