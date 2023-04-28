// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build enclave

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
	validator := ertvalidator.NewERTValidator()
	issuer := ertvalidator.NewERTIssuer()
	sealDirPrefix := filepath.Join(filepath.FromSlash("/edg"), "hostfs")
	sealDir := util.Getenv(constants.SealDir, constants.SealDirDefault())
	sealDir = filepath.Join(sealDirPrefix, sealDir)
	sealer := seal.NewAESGCMSealer()
	recovery := recovery.NewSinglePartyRecovery()
	run(validator, issuer, sealDir, sealer, recovery)
}
