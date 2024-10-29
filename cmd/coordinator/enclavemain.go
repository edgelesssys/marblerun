//go:build enclave

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"path/filepath"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/quote/ertvalidator"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/util"
)

func main() {
	log := newLogger()
	validator := ertvalidator.NewERTValidator(log)
	issuer := ertvalidator.NewERTIssuer()
	sealDirPrefix := filepath.Join(filepath.FromSlash("/edg"), "hostfs")
	sealDir := util.Getenv(constants.SealDir, constants.SealDirDefault())
	sealDir = filepath.Join(sealDirPrefix, sealDir)
	sealer := seal.NewAESGCMSealer()
	recovery := recovery.NewSinglePartyRecovery()
	run(log, validator, issuer, sealDir, sealer, recovery)
}
