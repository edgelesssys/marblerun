//go:build fakestore

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package store

import (
	"github.com/edgelesssys/marblerun/coordinator/store/distributed/k8sstore"
	"go.uber.org/zap"
)

// NewWithFakeK8s creates a new store with a fake k8sstore backed by files in sealDir.
func NewWithFakeK8s(sealer Sealer, name, namespace, sealDir string, log *zap.Logger) (*Store, error) {
	return &Store{
		quoteGenerator: &quoteRegenerator{},
		stateHandle:    k8sstore.NewWithFakeK8s(namespace, name, sealDir, log),
		sealer:         sealer,
		log:            log,
	}, nil
}
