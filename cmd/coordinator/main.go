//go:build !enclave

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/util"
)

func main() {
	log := newLogger()
	validator := quote.NewFailValidator()
	issuer := quote.NewFailIssuer()
	sealDir := util.Getenv(constants.SealDir, constants.SealDirDefault())
	sealer := seal.NewNoEnclaveSealer()
	recovery := recovery.NewSinglePartyRecovery()
	run(log, validator, issuer, sealDir, sealer, recovery)
}
