//go:build enclave

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/quote/ertvalidator"
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
	validator := ertvalidator.NewERTValidator(log)
	issuer := ertvalidator.NewERTIssuer()
	sealDirPrefix := filepath.Join(filepath.FromSlash("/edg"), "hostfs")
	sealDir := util.Getenv(constants.SealDir, constants.SealDirDefault())
	sealDir = filepath.Join(sealDirPrefix, sealDir)
	sealer := seal.NewAESGCMSealer(log)
	run(log, validator, issuer, sealDir, sealer)
}
