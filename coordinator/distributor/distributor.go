/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// Package distributor handles distribution and retrieval of key encryption keys (KEKs) to other Coordinator instances.
package distributor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"go.uber.org/zap"
)

// Distributor handles KEK distribution.
type Distributor struct {
	keyServiceName      string
	keyServiceNamespace string

	keyGenerator KeyGenerator
	keyRetriever keyRetriever
	keySharer    keySharer
	stateLoader  stateLoader

	keyChan chan []byte

	log *zap.Logger
}

// New creates a new Distributor.
func New(
	keyServiceName, keyServiceNamespace string,
	keyGenerator KeyGenerator, keyRetriever keyRetriever,
	keySharer keySharer, stateLoader stateLoader, log *zap.Logger,
) *Distributor {
	return &Distributor{
		keyServiceName:      keyServiceName,
		keyServiceNamespace: keyServiceNamespace,
		keyGenerator:        keyGenerator,
		keyRetriever:        keyRetriever,
		keySharer:           keySharer,
		stateLoader:         stateLoader,
		log:                 log,
		keyChan:             make(chan []byte, 1),
	}
}

// Start starts the Distributor asynchronously .
// It starts the key retriever and waits until it either the retriever returns a key,
// or a new key is set through other means. Then it starts the key sharer.
func (d *Distributor) Start() {
	d.log.Debug("Starting key distributor")
	go func() {
		if err := d.run(); err != nil {
			d.log.Fatal("Failed to run key distributor", zap.Error(err))
		}
	}()
}

func (d *Distributor) run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Check if we already have a key encryption key available.
	// If yes, the state was already successfully loaded from the storage backend.
	d.log.Debug("Checking if key encryption key is already available")
	keyEncryptionKey, err := d.keyGenerator.ExportKeyEncryptionKey(ctx)
	if err != nil {
		d.log.Debug("Instance does not have access to a key encryption key", zap.Error(err))

		var once sync.Once
		var wg sync.WaitGroup

		d.log.Debug("Trying to retrieve a key encryption key from another instance, or waiting for one to be generated through setting the manifest")
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Try to retrieve key from other instances.
			d.log.Info("Trying to retrieve key encryption key from other instances")
			key := d.keyRetriever.Run(ctx, d.keyServiceName, d.keyServiceNamespace)
			once.Do(func() {
				d.log.Info("Received key encryption key from another instance")
				keyEncryptionKey = key
				cancel()

				// Set keyEncryptionKey in storage backend and sealer.
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*30) // 30s timeout to set key
				defer cancel()
				if err := d.keyGenerator.SetKeyEncryptionKey(ctx, key); err != nil {
					d.log.Error("Failed to export key encryption key to storage backend", zap.Error(err))
				}
			})
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()

			// Wait for new keyEncryptionKey from setting the manifest.
			d.log.Info("Waiting for key encryption key to be loaded")
			select {
			case <-ctx.Done():
				return
			case key := <-d.keyChan:
				once.Do(func() {
					d.log.Info("New key encryption key loaded")
					keyEncryptionKey = key
					cancel()
				})
			}
		}()

		wg.Wait()

		// We have a key and can now load the state.
		recoveryData, _, err := d.stateLoader.LoadState()
		if err != nil {
			return fmt.Errorf("loading state with key encryption key: %w", err)
		}
		d.stateLoader.SetRecoveryData(recoveryData)
	}

	d.log.Debug("Key encryption key is available, starting to share it with other instances")
	return d.keySharer.Run(keyEncryptionKey, constants.KeyDistributorPort)
}

// StartSharing enables the distributor to share key encryption keys.
func (d *Distributor) StartSharing(ctx context.Context) error {
	key, err := d.keyGenerator.ExportKeyEncryptionKey(ctx)
	if err != nil {
		return err
	}

	d.keyChan <- key

	return nil
}

// Stub is a stub implementation of the Distributor.
type Stub struct{}

// StartSharing is a no-op.
func (d *Stub) StartSharing(_ context.Context) error { return nil }

// Start is a no-op.
func (d *Stub) Start() {}

// KeyGenerator generates and exports KEKs.
type KeyGenerator interface {
	ExportKeyEncryptionKey(context.Context) ([]byte, error)
	SetKeyEncryptionKey(context.Context, []byte) error
}
type keyRetriever interface {
	Run(ctx context.Context, namespace, serviceName string) []byte
}

type keySharer interface {
	Run(key []byte, port string) error
}

type stateLoader interface {
	LoadState() (recoveryData []byte, sealedState []byte, err error)
	SetRecoveryData(recoveryData []byte)
}
