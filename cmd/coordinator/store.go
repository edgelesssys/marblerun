//go:build !fakestore

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"github.com/edgelesssys/marblerun/coordinator/distributor"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/spf13/afero"
	"go.uber.org/zap"
)

func newDefaultStore(sealer seal.Sealer, sealDir string, log *zap.Logger) (store.Store, keyDistributor, error) {
	log.Info("Setting up default store")
	return stdstore.New(sealer, afero.NewOsFs(), sealDir, log), &distributor.Stub{}, nil
}
