/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package stdstore

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/store/request"
	"github.com/spf13/afero"
	"go.uber.org/zap"
)

const (
	// SealedDataFname is the file name in which the state is sealed on disk in seal_dir.
	SealedDataFname string = "sealed_data"

	// SealedKeyFname is the file name in which the key is sealed with the seal key on disk in seal_dir.
	SealedKeyFname string = "sealed_key"
)

// StdStore is the standard implementation of the Store interface.
type StdStore struct {
	data        map[string][]byte
	mux, txmux  sync.Mutex
	sealer      seal.Sealer
	hsmEnabler  hsmEnabler
	sealMode    seal.Mode
	oldSealMode seal.Mode

	fs              afero.Afero
	recoveryData    []byte
	oldRecoveryData []byte
	recoveryMode    bool
	sealDir         string

	log *zap.Logger
}

// New creates and initializes a new StdStore object.
func New(sealer seal.Sealer, hsmEnabler hsmEnabler, fs afero.Fs, sealDir string, log *zap.Logger) *StdStore {
	s := &StdStore{
		data:       make(map[string][]byte),
		sealer:     sealer,
		hsmEnabler: hsmEnabler,
		fs:         afero.Afero{Fs: fs},
		sealDir:    sealDir,
		log:        log,
	}

	return s
}

// Get retrieves a value from StdStore by Type and Name.
func (s *StdStore) Get(request string) ([]byte, error) {
	s.mux.Lock()
	s.log.Debug("Retrieving value from store", zap.String("request", request))
	value, ok := s.data[request]
	s.mux.Unlock()

	if ok {
		return value, nil
	}
	return nil, store.ErrValueUnset
}

// Put saves a value in StdStore by Type and Name.
func (s *StdStore) Put(request string, requestData []byte) error {
	s.log.Debug("Saving value to store", zap.String("request", request))
	tx := s.beginTransaction()
	defer tx.Rollback()
	if err := tx.Put(request, requestData); err != nil {
		return err
	}
	return tx.Commit(context.Background())
}

// Delete removes a value from StdStore.
func (s *StdStore) Delete(request string) error {
	s.log.Debug("Deleting value from store", zap.String("request", request))
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
	s.log.Debug("Creating iterator for store", zap.String("prefix", prefix))
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
func (s *StdStore) LoadState() (recoveryData, sealedData []byte, err error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	// load from fs
	s.log.Debug("Loading sealed state from file system", zap.String("filename", filepath.Join(s.sealDir, SealedDataFname)))
	sealedData, err = s.fs.ReadFile(filepath.Join(s.sealDir, SealedDataFname))
	if errors.Is(err, afero.ErrFileNotFound) {
		return nil, nil, nil
	} else if err != nil {
		s.log.Debug("Error reading sealed data", zap.Error(err))
		return nil, nil, err
	}

	s.log.Debug("Unsealing loaded state")
	encodedRecoveryData, stateRaw, err := s.sealer.Unseal(sealedData)
	if err != nil {
		s.log.Debug("Unsealing state failed", zap.Error(err))
		if !errors.Is(err, seal.ErrMissingEncryptionKey) {
			s.log.Debug("No encryption key found, entering recovery mode")
			s.recoveryMode = true
			return encodedRecoveryData, sealedData, fmt.Errorf("unsealing state: %w", err)
		}
		// Try to unseal encryption key from disk using product key
		// And retry unsealing the sealed data
		s.log.Debug("Trying to unseal encryption key")
		if err := s.unsealEncryptionKey(sealedData); err != nil {
			s.log.Debug("Unsealing encryption key failed, entering recovery mode", zap.Error(err))
			s.recoveryMode = true
			return encodedRecoveryData, sealedData, &seal.EncryptionKeyError{Err: err}
		}

		s.log.Debug("Retrying unsealing state")
		encodedRecoveryData, stateRaw, err = s.sealer.Unseal(sealedData)
		if err != nil {
			s.log.Debug("Unsealing state failed, entering recovery mode", zap.Error(err))
			s.recoveryMode = true
			return encodedRecoveryData, sealedData, fmt.Errorf("retry unsealing state with loaded key: %w", err)
		}
	}
	if len(stateRaw) == 0 {
		s.log.Debug("State is empty, nothing to do")
		return encodedRecoveryData, sealedData, nil
	}

	// load state
	s.log.Debug("Loading state from unsealed JSON blob")
	var loadedData map[string][]byte
	if err := json.Unmarshal(stateRaw, &loadedData); err != nil {
		return encodedRecoveryData, sealedData, err
	}
	if err := s.reloadOptions(loadedData); err != nil {
		return encodedRecoveryData, sealedData, err
	}

	s.data = loadedData
	return encodedRecoveryData, sealedData, nil
}

// SetRecoveryData sets the recovery data that is added to the sealed data.
func (s *StdStore) SetRecoveryData(recoveryData []byte) {
	s.log.Debug("Setting recovery data and removing recovery mode", zap.ByteString("recoveryData", recoveryData))
	s.oldRecoveryData = s.recoveryData
	s.recoveryData = recoveryData
	s.recoveryMode = false
}

// ResetRecoveryData restores the old recovery data.
func (s *StdStore) ResetRecoveryData() {
	s.log.Debug("Resetting recovery data to old recovery data", zap.ByteString("recoveryData", s.oldRecoveryData))
	s.recoveryData = s.oldRecoveryData
}

// BeginReadTransaction loads the sealed state and returns a read-only transaction.
func (s *StdStore) BeginReadTransaction(_ context.Context, encryptionKey []byte) (store.ReadTransaction, error) {
	s.log.Debug("Loading sealed state from file system", zap.String("filename", filepath.Join(s.sealDir, SealedDataFname)))
	sealedData, err := s.fs.ReadFile(filepath.Join(s.sealDir, SealedDataFname))
	if err != nil {
		return nil, fmt.Errorf("reading sealed data from disk: %w", err)
	}

	s.log.Debug("Unsealing state")
	_, data, err := s.sealer.UnsealWithKey(sealedData, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("unsealing state: %w", err)
	}

	s.log.Debug("Loading state from unsealed JSON blob")
	var loadedData map[string][]byte
	if err := json.Unmarshal(data, &loadedData); err != nil {
		return nil, fmt.Errorf("unmarshalling state: %w", err)
	}

	return &StdTransaction{
		// store is nil to prevent any writes or access to it
		// callers of this function must not call Commit
		store: nil,
		data:  loadedData,
		log:   s.log,
	}, nil
}

// SetEncryptionKey sets the encryption key for sealing and unsealing.
func (s *StdStore) SetEncryptionKey(encryptionKey []byte, mode seal.Mode) {
	s.log.Debug("Setting encryption key", zap.Int("mode", int(mode)))
	s.sealer.SetEncryptionKey(encryptionKey)
	s.oldSealMode = s.sealMode
	s.sealMode = mode
}

// ResetEncryptionKey restores the old encryption key.
func (s *StdStore) ResetEncryptionKey() {
	s.log.Debug("Resetting encryption key", zap.Int("mode", int(s.oldSealMode)))
	s.sealMode = s.oldSealMode
	s.sealer.ResetEncryptionKey()
}

// SealEncryptionKey seals the encryption key and writes it to disk.
func (s *StdStore) SealEncryptionKey(additionalData []byte) error {
	s.log.Debug("Sealing state encryption key")
	if s.sealMode == seal.ModeDisabled {
		s.log.Debug("Sealing disabled, nothing to do")
		return nil
	}

	additionalDataHash := sha256.Sum256(additionalData)
	s.log.Debug("Sealing state encryption key with additional data", zap.String("additionalData", hex.EncodeToString(additionalDataHash[:])))
	encryptedKey, err := s.sealer.SealEncryptionKey(additionalDataHash[:], s.sealMode)
	if err != nil {
		return fmt.Errorf("encrypting data key: %w", err)
	}

	// Write the sealed encryption key to disk
	s.log.Debug("Writing sealed encryption key to disk", zap.String("filename", filepath.Join(s.sealDir, SealedKeyFname)))
	if err = s.atomicWriteFile(SealedKeyFname, encryptedKey); err != nil {
		return fmt.Errorf("writing encrypted key to disk: %w", err)
	}

	return nil
}

// GetCiphertext gets the sealed data from the backend.
func (s *StdStore) GetCiphertext() ([]byte, error) {
	sealedData, err := s.fs.ReadFile(filepath.Join(s.sealDir, SealedDataFname))
	if err != nil {
		return nil, fmt.Errorf("reading sealed data from disk: %w", err)
	}
	return sealedData, nil
}

// TestKey tests if the given key can be used to decrypt the given ciphertext.
func (s *StdStore) TestKey(key, ciphertext []byte) bool {
	s.mux.Lock()
	defer s.mux.Unlock()
	_, _, err := s.sealer.UnsealWithKey(ciphertext, key)
	return err == nil
}

// PersistRecoveryData persists the given recovery data to disk if it got lost.
func (s *StdStore) PersistRecoveryData(recoveryData []byte) error {
	currentData, err := s.fs.ReadFile(filepath.Join(s.sealDir, SealedDataFname))
	if err != nil {
		return fmt.Errorf("reading sealed data from disk: %w", err)
	}

	if len(currentData) < 4 || binary.LittleEndian.Uint32(currentData) != 0 {
		return errors.New("expected empty recovery data, refusing to overwrite")
	}

	sealedData := binary.LittleEndian.AppendUint32(nil, uint32(len(recoveryData)))
	sealedData = append(sealedData, recoveryData...)
	sealedData = append(sealedData, currentData[4:]...)

	return s.atomicWriteFile(filepath.Join(s.sealDir, SealedDataFname), sealedData)
}

func (s *StdStore) beginTransaction() *StdTransaction {
	s.log.Debug("Starting new store transaction")
	tx := StdTransaction{store: s, data: map[string][]byte{}, log: s.log}
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
	s.log.Debug("Committing store transaction", zap.Bool("recoveryMode", s.recoveryMode), zap.Int("sealMode", int(s.sealMode)))
	dataRaw, err := json.Marshal(data)
	if err != nil {
		return err
	}

	s.mux.Lock()
	defer s.mux.Unlock()
	if !s.recoveryMode && s.sealMode != seal.ModeDisabled {
		s.log.Debug("Sealing transaction data")
		sealedData, err := s.sealer.Seal(s.recoveryData, dataRaw)
		if err != nil {
			return err
		}

		additionalData := sha256.Sum256(sealedData)
		s.log.Debug("Sealing encryption key", zap.String("additionalData", hex.EncodeToString(additionalData[:])))
		encryptedKey, err := s.sealer.SealEncryptionKey(additionalData[:], s.sealMode)
		if err != nil {
			return fmt.Errorf("sealing encryption key: %w", err)
		}

		// atomically replace the sealed data file
		s.log.Debug("Writing sealed transaction data to disk", zap.String("filename", filepath.Join(s.sealDir, SealedDataFname)))
		if err := s.atomicWriteFile(SealedDataFname, sealedData); err != nil {
			return fmt.Errorf("writing sealed data file: %w", err)
		}

		// atomically replace the sealed key file
		s.log.Debug("Writing sealed encryption key to disk", zap.String("filename", filepath.Join(s.sealDir, SealedKeyFname)))
		if err := s.atomicWriteFile(SealedKeyFname, encryptedKey); err != nil {
			return fmt.Errorf("writing encrypted key to disk: %w", err)
		}
	}

	s.data = data
	s.log.Debug("Transaction committed")
	s.txmux.Unlock()

	return nil
}

// unsealEncryptionKey sets the seal key for the store's sealer by loading the encrypted key from disk.
func (s *StdStore) unsealEncryptionKey(sealedData []byte) error {
	s.log.Debug("Loading sealed encryption key from disk", zap.String("filename", filepath.Join(s.sealDir, SealedKeyFname)))
	encryptedKey, err := s.fs.ReadFile(filepath.Join(s.sealDir, SealedKeyFname))
	if err != nil {
		return fmt.Errorf("reading encrypted key from disk: %w", err)
	}

	additionalData := sha256.Sum256(sealedData)
	s.log.Debug("Unsealing encryption key", zap.String("additionalData", hex.EncodeToString(additionalData[:])))
	key, err := s.sealer.UnsealEncryptionKey(encryptedKey, additionalData[:])
	if err != nil {
		return fmt.Errorf("decrypting data key: %w", err)
	}
	s.sealer.SetEncryptionKey(key)
	return nil
}

// atomicWriteFile writes data to a temporary file and then atomically replaces the target file.
func (s *StdStore) atomicWriteFile(fileName string, data []byte) error {
	filePath := filepath.Join(s.sealDir, fileName)
	filePathTmp := filePath + ".tmp"
	filePathOld := filePath + ".old"
	if err := s.fs.WriteFile(filePathTmp, data, 0o600); err != nil {
		return fmt.Errorf("writing temporary file: %w", err)
	}
	if err := s.fs.Rename(filePath, filePathOld); err != nil && !errors.Is(err, afero.ErrFileNotFound) {
		return fmt.Errorf("backing up old file: %w", err)
	}
	if err := s.fs.Rename(filePathTmp, filePath); err != nil {
		return fmt.Errorf("replacing file: %w", err)
	}
	return nil
}

func (s *StdStore) reloadOptions(rawState map[string][]byte) error {
	s.log.Debug("Reloading manifest options")
	rawMnf, ok := rawState[request.Manifest]
	if !ok {
		return nil // no manifest set
	}

	var mnf manifest.Manifest
	if err := json.Unmarshal(rawMnf, &mnf); err != nil {
		return fmt.Errorf("unmarshaling manifest: %w", err)
	}

	s.sealMode = seal.ModeFromString(mnf.Config.SealMode)
	s.log.Debug("Seal mode set", zap.Int("sealMode", int(s.sealMode)))

	s.hsmEnabler.SetEnabled(mnf.HasFeatureEnabled(manifest.FeatureAzureHSMSealing))
	return nil
}

// StdTransaction is a transaction for StdStore.
type StdTransaction struct {
	store *StdStore
	data  map[string][]byte
	log   *zap.Logger
}

// Get retrieves a value.
func (t *StdTransaction) Get(request string) ([]byte, error) {
	t.log.Debug("Retrieving value from transaction", zap.String("request", request))
	if value, ok := t.data[request]; ok {
		return value, nil
	}
	return nil, store.ErrValueUnset
}

// Put saves a value.
func (t *StdTransaction) Put(request string, requestData []byte) error {
	t.log.Debug("Saving value to transaction", zap.String("request", request))
	t.data[request] = requestData
	return nil
}

// Delete removes a value.
func (t *StdTransaction) Delete(request string) error {
	t.log.Debug("Deleting value from transaction", zap.String("request", request))
	delete(t.data, request)
	return nil
}

// Iterator returns an iterator for all keys in the transaction with a given prefix.
func (t *StdTransaction) Iterator(prefix string) (store.Iterator, error) {
	t.log.Debug("Creating iterator for transaction", zap.String("prefix", prefix))
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
	t.log.Debug("Committing transaction")
	if err := t.store.commit(t.data); err != nil {
		return err
	}
	t.store = nil
	return nil
}

// Rollback aborts a transaction.
func (t *StdTransaction) Rollback() {
	t.log.Debug("Rolling back transaction")
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

type hsmEnabler interface {
	SetEnabled(enabled bool)
}
