/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// Package store provides an implementation of the store interface for distributed Coordinators.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/kube"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/store/distributed/k8sstore"
	"github.com/edgelesssys/marblerun/coordinator/store/distributed/transaction"
	"github.com/edgelesssys/marblerun/coordinator/store/distributed/wrapper"
	"github.com/edgelesssys/marblerun/coordinator/store/request"
	"go.uber.org/zap"
)

// Store is an implementation of the store interface for distributed Coordinators.
type Store struct {
	stateHandle    stateHandle
	quoteGenerator regenerator
	sealer         Sealer
	recoveryData   []byte

	recoveryMode bool
	// tmpRecoveryState is a map to hold the state during recovery.
	tmpRecoveryState map[string][]byte

	mux, txMux sync.Mutex

	// modeLock is used to ensure the cached sealing key and mode is only updated in one place.
	modeLock sync.Mutex
	// sealMode is the current seal mode.
	sealMode seal.Mode

	log *zap.Logger
}

// New creates and initializes a new store for distributed Coordinators.
func New(sealer Sealer, name, namespace string, log *zap.Logger) (*Store, error) {
	clientset, err := kube.GetClient()
	if err != nil {
		return nil, err
	}

	return &Store{
		quoteGenerator: &quoteRegenerator{},
		stateHandle:    k8sstore.New(clientset, namespace, name, log),
		sealer:         sealer,
		log:            log,
	}, nil
}

// SetQuoteGenerator adds a quote generator to the store.
func (s *Store) SetQuoteGenerator(qg quoteGenerator) {
	s.log.Debug("Setting quote generator")
	s.quoteGenerator.SetGenerator(qg)
}

// SetEncryptionKey sets the sealing key for the store.
//
// The sealing key will be updated during recovery, or when setting the manifest.
// In this case, this key needs to be used when sealing the new state,
// therefore we cache the key here, so that it can be used during the next seal operation.
func (s *Store) SetEncryptionKey(key []byte, mode seal.Mode) {
	// Lock access to the cached key
	s.modeLock.Lock()
	defer s.modeLock.Unlock()
	s.log.Debug("Setting encryption key", zap.Int("mode", int(mode)))
	s.sealer.SetEncryptionKey(key)
	s.sealer.SetSealMode(mode)
	s.sealMode = mode
}

// SealEncryptionKey seals the encryption key with the current seal mode.
func (s *Store) SealEncryptionKey(_ []byte) error {
	s.modeLock.Lock()
	defer s.modeLock.Unlock()
	return s.sealer.SealKEK(context.TODO(), s.sealMode)
}

// GetSealMode returns the current seal mode.
func (s *Store) GetSealMode() seal.Mode {
	s.modeLock.Lock()
	defer s.modeLock.Unlock()
	return s.sealMode
}

// SetRecoveryData sets the recovery data used to recover the sealed state.
func (s *Store) SetRecoveryData(recoveryData []byte) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.log.Debug("Setting recovery data and removing recovery mode", zap.ByteString("recoveryData", recoveryData))

	s.recoveryData = recoveryData
	s.recoveryMode = false
}

// LoadState loads sealed data from the backend.
func (s *Store) LoadState() ([]byte, []byte, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	encodedRecoveryData, rawState, stateRef, err := s.loadState(context.Background())
	if err == nil {
		// clear temporary recovery state if we successfully loaded the state
		s.tmpRecoveryState = nil

		if err := s.reloadSealMode(rawState); err != nil {
			return nil, nil, err
		}
	}

	var sealedData []byte
	if stateRef != nil {
		sealedData = stateRef.SealedData
	}
	return encodedRecoveryData, sealedData, err
}

// BeginTransaction starts a new transaction by loading the state from the backend.
func (s *Store) BeginTransaction(ctx context.Context) (tx store.Transaction, err error) {
	// Lock transaction mutex first to prevent lock starvation
	// Unlock it if an error occurs
	s.txMux.Lock()
	defer func() {
		if err != nil {
			s.UnlockTxMux()
		}
	}()

	s.mux.Lock()
	defer s.mux.Unlock()
	s.log.Debug("Starting new store transaction")

	recoveryData, data, state, err := s.loadState(ctx)

	// If there's more than one replica, there are edge cases where an instance is running that doesn't
	// have the recovery data set. If that's the case, take the recovery data from the state.
	if s.recoveryData == nil {
		s.recoveryData = recoveryData
	}

	if err == nil {
		tx := transaction.New(s, data, state, s.log)

		if err := s.quoteGenerator.Regenerate(tx); err != nil {
			return nil, fmt.Errorf("regenerating quote: %w", err)
		}

		return tx, nil
	}

	// If we are in recovery mode, unsealing the state will fail
	// However, we still want to be able to start a transaction
	// Therefore, we return a transaction as long as we have a valid state reference
	// This allows us to recover the state later on, or overwrite it with a new state
	if !s.recoveryMode || state == nil {
		return nil, err
	}

	// Use the temporary state saved in memory during recovery
	if s.tmpRecoveryState == nil {
		s.tmpRecoveryState = make(map[string][]byte)
	}

	data = make(map[string][]byte)
	for k, v := range s.tmpRecoveryState {
		data[k] = v
	}

	return transaction.New(s, data, state, s.log), nil
}

// BeginReadTransaction starts a read-only transaction on the sealed state of the store.
func (s *Store) BeginReadTransaction(ctx context.Context, encryptionKey []byte) (store.ReadTransaction, error) {
	s.log.Debug("Loading sealed state from backend")
	state, err := s.stateHandle.GetState(ctx)
	if err != nil {
		return nil, err
	}

	if state.SealedData == nil {
		return nil, errors.New("no sealed data found in state")
	}

	s.log.Debug("Unsealing state")
	_, stateRaw, err := s.sealer.UnsealWithKey(state.SealedData, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("unsealing state: %w", err)
	}

	s.log.Debug("Loading state from unsealed JSON blob")
	var loadedData map[string][]byte
	if err := json.Unmarshal(stateRaw, &loadedData); err != nil {
		return nil, fmt.Errorf("unmarshalling state: %w", err)
	}

	return transaction.New(stubCommitter{}, loadedData, state, s.log), nil
}

// Commit updates the given state with the given data and saves it to the backend.
func (s *Store) Commit(ctx context.Context, state *transaction.State, data map[string][]byte) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.modeLock.Lock()
	defer s.modeLock.Unlock()
	s.log.Debug("Committing store transaction", zap.Bool("recoveryMode", s.recoveryMode), zap.Int("sealMode", int(s.sealMode)))

	// Don't commit anything to backend if we're in recovery mode
	// Instead, keep a copy of the state in memory and return
	if s.recoveryMode {
		s.log.Debug("Storing committed state in memory during recovery")
		s.tmpRecoveryState = data
		s.UnlockTxMux()
		return nil
	}

	newData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshaling state: %w", err)
	}

	s.log.Debug("Sealing transaction data")
	sealedData, err := s.sealer.Seal(s.recoveryData, newData)
	if err != nil {
		s.log.Debug("Sealing transaction data failed", zap.Error(err))
		// Sealing failed, try to recover using sealed key, or generate a new one
		if state.SealedKey == nil {
			// No encryption key in backend
			// Generate a new encryption key
			s.log.Debug("No encryption key found in state, generating a new one")
			encryptionKey, err := seal.GenerateEncryptionKey()
			if err != nil {
				return err
			}
			s.sealer.SetEncryptionKey(encryptionKey)
		} else if err := s.unsealEncryptionKey(state); err != nil {
			return &seal.EncryptionKeyError{Err: err}
		}

		s.log.Debug("Retrying sealing of transaction data")
		sealedData, err = s.sealer.Seal(s.recoveryData, newData)
		if err != nil {
			return err
		}
	}

	// Bind the sealed data to the encryption key
	additionalData := sha256.Sum256(sealedData)
	s.log.Debug("Sealing encryption key with additional Data", zap.String("additionalData", hex.EncodeToString(additionalData[:])))
	sealedKey, err := s.sealer.SealEncryptionKey(additionalData[:], s.sealMode)
	if err != nil {
		return fmt.Errorf("sealing encryption key: %w", err)
	}

	// Update state with sealed data and save it to backend
	s.log.Debug("Transaction data sealed successfully, saving state to backend")
	state.SealedData = sealedData
	state.SealedKey = sealedKey
	if err := s.stateHandle.SaveState(ctx, state); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	s.UnlockTxMux()
	return nil
}

// UnlockTxMux unlocks the transaction mutex of the store.
func (s *Store) UnlockTxMux() {
	s.txMux.Unlock()
}

// GetCiphertext gets the sealed data from the backend.
func (s *Store) GetCiphertext() ([]byte, error) {
	state, err := s.stateHandle.GetState(context.Background())
	if err != nil {
		return nil, err
	}
	return state.SealedData, nil
}

// TestKey tests if the given key can be used to decrypt the given ciphertext.
func (s *Store) TestKey(key, ciphertext []byte) bool {
	s.mux.Lock()
	defer s.mux.Unlock()
	_, _, err := s.sealer.UnsealWithKey(ciphertext, key)
	return err == nil
}

// PersistRecoveryData persists the given recovery data to the backend if it got lost.
func (s *Store) PersistRecoveryData(recoveryData []byte) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	ctx := context.Background()

	state, err := s.stateHandle.GetState(ctx)
	if err != nil {
		return err
	}

	currentData := state.SealedData
	if len(currentData) < 4 || binary.LittleEndian.Uint32(currentData) != 0 {
		return errors.New("expected empty recovery data, refusing to overwrite")
	}

	state.SealedData = binary.LittleEndian.AppendUint32(nil, uint32(len(recoveryData)))
	state.SealedData = append(state.SealedData, recoveryData...)
	state.SealedData = append(state.SealedData, currentData[4:]...)

	return s.stateHandle.SaveState(ctx, state)
}

// loadState loads the distributed state from the backend and unseals it.
//
// This function must return data and a state reference, as long as loading the state from backend succeeded.
func (s *Store) loadState(ctx context.Context) (recoveryData []byte, data map[string][]byte, stateRef *transaction.State, err error) {
	s.log.Debug("Loading state from backend")
	state, err := s.stateHandle.GetState(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	data = make(map[string][]byte)
	if state.SealedData == nil {
		s.log.Debug("No sealed data found in state, returning state handle")
		// No state exists yet, return empty state
		return nil, data, state, nil
	}

	// Decrypt sealed data
	s.log.Debug("Trying to unseal state data")
	encodedRecoveryData, stateRaw, err := s.sealer.Unseal(state.SealedData)
	if err != nil {
		// Unsealing failed, try to recover using sealed key
		// Decrypt encryption key from the backend and set it for the sealer
		s.log.Debug("Unsealing state data failed", zap.Error(err))
		s.log.Debug("Trying to unseal encryption key")
		if err := s.unsealEncryptionKey(state); err != nil {
			s.log.Debug("Unsealing encryption key failed, entering recovery mode", zap.Error(err))
			s.recoveryMode = true
			return encodedRecoveryData, data, state, &seal.EncryptionKeyError{Err: err}
		}

		// Retry unsealing
		s.log.Debug("Retrying unsealing of state data")
		encodedRecoveryData, stateRaw, err = s.sealer.Unseal(state.SealedData)
		if err != nil {
			s.log.Debug("Unsealing state data failed, entering recovery mode", zap.Error(err))
			s.recoveryMode = true
			return encodedRecoveryData, data, state, fmt.Errorf("unsealing state: %w", err)
		}
	}

	s.log.Debug("Loading state from unsealed JSON blob")
	if err := json.Unmarshal(stateRaw, &data); err != nil {
		return encodedRecoveryData, data, state, fmt.Errorf("unmarshaling state: %w", err)
	}

	return encodedRecoveryData, data, state, nil
}

func (s *Store) unsealEncryptionKey(state *transaction.State) error {
	s.log.Debug("Trying to unseal encryption key from state")
	if state.SealedKey == nil {
		return errors.New("no encryption key found in state")
	}

	// Decrypt encryption key from the backend and set it for the sealer
	additionalData := sha256.Sum256(state.SealedData)
	s.log.Debug("Unsealing encryption key with additional Data", zap.String("additionalData", hex.EncodeToString(additionalData[:])))
	key, err := s.sealer.UnsealEncryptionKey(state.SealedKey, additionalData[:])
	if err != nil {
		return err
	}

	s.sealer.SetEncryptionKey(key)
	return nil
}

func (s *Store) reloadSealMode(rawState map[string][]byte) error {
	s.log.Debug("Reloading seal mode")
	rawMnf, ok := rawState[request.Manifest]
	if !ok {
		return nil // no manifest set
	}

	var mnf manifest.Manifest
	if err := json.Unmarshal(rawMnf, &mnf); err != nil {
		return fmt.Errorf("unmarshaling manifest: %w", err)
	}

	s.sealMode = seal.ModeFromString(mnf.Config.SealMode)
	s.sealer.SetSealMode(seal.ModeFromString(mnf.Config.SealMode))
	s.log.Debug("Seal mode set", zap.Int("sealMode", int(s.sealMode)))
	return nil
}

// Sealer extends the default Sealer interface with SealKEK.
type Sealer interface {
	seal.Sealer
	SealKEK(context.Context, seal.Mode) error
	SetSealMode(seal.Mode)
}

type quoteRegenerator struct {
	quoteSet       bool
	quoteLock      sync.Mutex
	quoteGenerator quoteGenerator
}

// Regenerate generates a new quote using information from the transaction.
func (q *quoteRegenerator) Regenerate(tx store.Transaction) (err error) {
	q.quoteLock.Lock()
	defer q.quoteLock.Unlock()

	// If a quote has already been set, we don't need to generate a new one
	// If no quote generator is set, we can't generate a quote. This is the case
	// when we have just created a new Core, and the instance has recovered its state.
	if q.quoteSet || q.quoteGenerator == nil {
		return nil
	}

	// Check if we have a certificate to generate a quote with
	data := wrapper.New(tx)
	rootCert, err := data.GetCertificate(constants.SKCoordinatorRootCert)
	if err != nil {
		if errors.Is(err, store.ErrValueUnset) {
			return nil
		}
		return err
	}

	if err = q.quoteGenerator.GenerateQuote(rootCert.Raw); err != nil {
		return err
	}

	if _, err := data.GetRawManifest(); err == nil {
		q.quoteSet = true
	}
	return nil
}

// SetGenerator sets the quote generator.
func (q *quoteRegenerator) SetGenerator(generator quoteGenerator) {
	q.quoteGenerator = generator
}

type stubCommitter struct{}

func (stubCommitter) Commit(context.Context, *transaction.State, map[string][]byte) error { return nil }

func (stubCommitter) UnlockTxMux() {}

type stateHandle interface {
	GetState(context.Context) (*transaction.State, error)
	SaveState(context.Context, *transaction.State) error
}

type quoteGenerator interface {
	GenerateQuote(cert []byte) error
}

type regenerator interface {
	Regenerate(tx store.Transaction) error
	SetGenerator(quoteGenerator)
}
