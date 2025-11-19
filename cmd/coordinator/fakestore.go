//go:build fakestore

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"context"
	"fmt"

	"github.com/edgelesssys/marblerun/coordinator/distributor"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	dseal "github.com/edgelesssys/marblerun/coordinator/seal/distributed"
	"github.com/edgelesssys/marblerun/coordinator/store"
	dstore "github.com/edgelesssys/marblerun/coordinator/store/distributed"
	"go.uber.org/zap"
)

func newDefaultStore(sealer seal.Sealer, sealDir string, log *zap.Logger) (store.Store, keyDistributor, error) {
	log.Info("Setting up fake k8s store")

	const namespace = "fake"

	// Wrap sealer for fake distributed store
	esealer, err := dseal.NewWithFakeK8s(sealer, "key", namespace, sealDir, log)
	if err != nil {
		return nil, nil, fmt.Errorf("setting up sealer: %w", err)
	}

	// Create fake distributed store
	store, err := dstore.NewWithFakeK8s(esealer, "state", namespace, sealDir, log)
	if err != nil {
		return nil, nil, fmt.Errorf("setting up store backend: %w", err)
	}

	return store, &fakeKeyDistributor{keygen: esealer}, nil
}

type fakeKeyDistributor struct {
	keygen distributor.KeyGenerator
}

// StartSharing exports the KEK.
func (d *fakeKeyDistributor) StartSharing(ctx context.Context) error {
	_, err := d.keygen.ExportKeyEncryptionKey(ctx)
	return err
}

// Start is a no-op.
func (d *fakeKeyDistributor) Start() {}
