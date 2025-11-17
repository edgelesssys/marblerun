/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package store

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/store/distributed/transaction"
	"github.com/edgelesssys/marblerun/coordinator/store/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/zap/zaptest"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestDistributedStore(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	ctx := context.Background()
	key, otherKey := "key", "other-key"
	value, otherValue := []byte("value"), []byte("other-value")
	encryptionKey := bytes.Repeat([]byte{0x09}, 16)
	sealMode := seal.ModeProductKey

	log := zaptest.NewLogger(t)
	stateHandle := &fakeStateHandle{}
	sealer := &noEnclaveSealer{NoEnclaveSealer: seal.NewNoEnclaveSealer(log)}
	store := &Store{
		quoteGenerator: &stubRegenerator{},
		stateHandle:    stateHandle,
		sealer:         sealer,
		log:            log,
	}

	// Load state
	_, _, err := store.LoadState()
	assert.NoError(err)

	// Start and commit a transaction
	// This will create a random encryption key
	tx, err := store.BeginTransaction(ctx)
	require.NoError(err)
	err = tx.Put(key, value)
	require.NoError(err)
	err = tx.Put(request.Manifest, []byte(`{"Config":{"SealMode":"ProductKey"}}`)) // Add manifest with seal mode
	require.NoError(err)
	err = tx.Commit(ctx)
	require.NoError(err)

	// Start a new transaction, and reset the encryption key mid-transaction
	tx, err = store.BeginTransaction(ctx)
	require.NoError(err)
	err = tx.Put(key, value)
	require.NoError(err)

	// Before setting an encryption key, sealing should be disabled
	assert.Equal(seal.ModeDisabled, store.GetSealMode())

	// Set new encryption key
	store.SetEncryptionKey(encryptionKey, sealMode)
	assert.Equal(sealMode, store.GetSealMode())
	assert.Equal(sealMode, sealer.sealMode)

	err = tx.Commit(ctx)
	require.NoError(err)

	// Remove encryption key to trigger recovery
	stateHandle.key = nil
	store.sealer = &noEnclaveSealer{NoEnclaveSealer: seal.NewNoEnclaveSealer(log)}

	// Load state, should be in recovery mode
	recoveryData, _, err := store.LoadState()
	require.Error(err)
	require.True(store.recoveryMode)

	// Save some state while in recovery mode
	recoveryTx, err := store.BeginTransaction(ctx)
	require.NoError(err)
	_, err = recoveryTx.Get(key)
	assert.Error(err)
	err = recoveryTx.Put(otherKey, otherValue)
	assert.NoError(err)
	err = recoveryTx.Commit(ctx)
	assert.NoError(err)

	// Recover state
	store.SetRecoveryData(recoveryData)
	store.SetEncryptionKey(encryptionKey, seal.ModeProductKey)
	assert.Equal(sealMode, store.GetSealMode())
	assert.Equal(sealMode, sealer.sealMode)

	// Check state after recovery
	tx, err = store.BeginTransaction(ctx)
	require.NoError(err)
	val, err := tx.Get(key)
	assert.NoError(err)
	assert.Equal(value, val)
	_, err = tx.Get(otherKey)
	assert.Error(err)
	err = tx.Put(key, otherValue)
	assert.NoError(err)
	err = tx.Commit(ctx)
	require.NoError(err)

	// Create a new store with the same state handle
	// This should load the encryption key from the state handle
	store2 := &Store{
		quoteGenerator: &stubRegenerator{},
		stateHandle:    stateHandle,
		sealer:         &noEnclaveSealer{NoEnclaveSealer: seal.NewNoEnclaveSealer(log)},
		log:            log,
	}

	_, _, err = store2.LoadState()
	assert.NoError(err)
	assert.Equal(sealMode, store2.GetSealMode())
	assert.Equal(sealMode, sealer.sealMode)

	tx, err = store2.BeginTransaction(ctx)
	require.NoError(err)
	val, err = tx.Get(key)
	assert.NoError(err)
	assert.Equal(otherValue, val)
}

func TestConcurrency(t *testing.T) {
	testCases := map[string]struct {
		sealer Sealer
	}{
		"recovery mode": {
			sealer: &safeMockSealer{
				unsealError: assert.AnError,
			},
		},
		"normal operation": {
			sealer: &safeMockSealer{},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			stateHandle := &fakeStateHandle{
				state: []byte(`{"some":"dmFsdWU="}`),
				key:   []byte("key"),
			}
			_, err := tc.sealer.Seal([]byte{}, stateHandle.state)
			require.NoError(err)

			store := &Store{
				quoteGenerator: &stubRegenerator{},
				stateHandle:    stateHandle,
				sealer:         tc.sealer,
				log:            zaptest.NewLogger(t),
			}

			parallelProcesses := 500
			var wg sync.WaitGroup
			wg.Add(parallelProcesses)
			for i := 0; i < parallelProcesses; i++ {
				go func() {
					defer wg.Done()

					ctx := context.Background()
					tx, err := store.BeginTransaction(ctx)
					require.NoError(err)
					defer tx.Rollback()

					err = tx.Commit(ctx)
					if err != nil {
						assert.ErrorIs(err, errOutOfDate)
					}
				}()
			}

			wg.Wait()
		})
	}
}

func TestGetCiphertextAndTestKey(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	ctx := context.Background()
	log := zaptest.NewLogger(t)
	stateHandle := &fakeStateHandle{}
	sealer := &noEnclaveSealer{NoEnclaveSealer: seal.NewNoEnclaveSealer(log)}
	store := &Store{
		quoteGenerator: &stubRegenerator{},
		stateHandle:    stateHandle,
		sealer:         sealer,
		log:            log,
	}

	// Commit a transaction to create the encryption key and ciphertext
	tx, err := store.BeginTransaction(ctx)
	require.NoError(err)
	require.NoError(tx.Commit(ctx))

	ciphertext, err := store.GetCiphertext()
	require.NoError(err)
	assert.False(store.TestKey(make([]byte, 16), ciphertext))
	assert.True(store.TestKey(stateHandle.key, ciphertext))
}

func TestPersistRecoveryData(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	ctx := context.Background()
	log := zaptest.NewLogger(t)
	stateHandle := &fakeStateHandle{}
	sealer := &noEnclaveSealer{NoEnclaveSealer: seal.NewNoEnclaveSealer(log)}
	store := &Store{
		quoteGenerator: &stubRegenerator{},
		stateHandle:    stateHandle,
		sealer:         sealer,
		log:            log,
	}

	recoveryData := []byte("recoveryData")
	const key = "key"
	value := []byte("value")

	// No state yet
	require.Error(store.PersistRecoveryData(recoveryData))

	// Commit a transaction to create a state (without recovery data)
	tx, err := store.BeginTransaction(ctx)
	require.NoError(err)
	require.NoError(tx.Put(key, value))
	require.NoError(tx.Commit(ctx))

	// Persist recovery data
	require.NoError(store.PersistRecoveryData(recoveryData))

	// Persist should fail if there's already recovery data
	assert.Error(store.PersistRecoveryData(recoveryData))

	// Read value to verify the state is still intact
	tx, err = store.BeginTransaction(ctx)
	require.NoError(err)
	actualValue, err := tx.Get(key)
	require.NoError(err)
	tx.Rollback()
	assert.Equal(value, actualValue)

	// Verify recovery data
	assert.Equal(recoveryData, store.recoveryData)
}

var errOutOfDate = errors.New("a different transaction has already been committed, apply changes and retry")

type noEnclaveSealer struct {
	*seal.NoEnclaveSealer
	sealMode seal.Mode
}

func (s *noEnclaveSealer) SealKEK(_ context.Context, mode seal.Mode) error {
	s.sealMode = mode
	return nil
}

func (s *noEnclaveSealer) SetSealMode(mode seal.Mode) {
	s.sealMode = mode
}

type fakeStateHandle struct {
	state []byte
	key   []byte

	mux       sync.Mutex
	txCounter uint
}

func (f *fakeStateHandle) GetState(_ context.Context) (*transaction.State, error) {
	f.mux.Lock()
	defer f.mux.Unlock()

	return &transaction.State{
		SealedData: f.state,
		SealedKey:  f.key,
		StateRef:   f.txCounter,
	}, nil
}

func (f *fakeStateHandle) SaveState(_ context.Context, state *transaction.State) error {
	f.mux.Lock()
	defer f.mux.Unlock()

	txCounter, ok := state.StateRef.(uint)
	if !ok {
		return errors.New("invalid state ref")
	}

	if txCounter != f.txCounter {
		return errOutOfDate
	}

	f.state = state.SealedData
	f.key = state.SealedKey
	f.txCounter++

	return nil
}

type safeMockSealer struct {
	mux sync.Mutex

	key             []byte
	data            []byte
	unencryptedData []byte
	unsealError     error
}

// Unseal implements the Sealer interface.
func (s *safeMockSealer) Unseal(_ []byte) ([]byte, []byte, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	return s.unencryptedData, s.data, s.unsealError
}

func (s *safeMockSealer) UnsealWithKey(_, _ []byte) ([]byte, []byte, error) {
	return s.Unseal(nil)
}

// Seal implements the Sealer interface.
func (s *safeMockSealer) Seal(unencryptedData []byte, toBeEncrypted []byte) ([]byte, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	s.unencryptedData = unencryptedData
	s.data = toBeEncrypted
	return toBeEncrypted, nil
}

// SealEncryptionKey implements the Sealer interface.
// Since the MockSealer does not support sealing with an enclave key, it returns the key as is.
func (s *safeMockSealer) SealEncryptionKey(_ []byte, _ seal.Mode) ([]byte, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	return s.key, nil
}

// SetEncryptionKey implements the Sealer interface.
func (s *safeMockSealer) SetEncryptionKey(key []byte) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.key = key
}

// UnsealEncryptionKey implements the Sealer interface.
func (s *safeMockSealer) UnsealEncryptionKey(key, _ []byte) ([]byte, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	return key, nil
}

func (*safeMockSealer) SealKEK(context.Context, seal.Mode) error { return nil }

func (s *safeMockSealer) SetSealMode(seal.Mode) {}

type stubRegenerator struct {
	err error
}

func (s *stubRegenerator) Regenerate(_ store.Transaction) error {
	return s.err
}

func (s *stubRegenerator) SetGenerator(_ quoteGenerator) {}
