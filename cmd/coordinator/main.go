//go:build !enclave

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"fmt"
	"os"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/internal/logging"
	"github.com/edgelesssys/marblerun/util"
)

func main() {
	log, err := logging.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create logger: %s\n", err)
		os.Exit(1)
	}
	validator := quote.NewFailValidator()
	issuer := quote.NewFailIssuer()
	sealDir := util.Getenv(constants.SealDir, constants.SealDirDefault())
	sealer := seal.NewNoEnclaveSealer(log)
	recovery := recovery.NewSinglePartyRecovery()
	run(log, validator, issuer, sealDir, sealer, recovery)
}
