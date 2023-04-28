// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build !enclave

package main

import (
	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/util"

	_ "github.com/edgelesssys/marblerun/apidoc" // This line is necessary for go-swagger
)

func main() {
	validator := quote.NewFailValidator()
	issuer := quote.NewFailIssuer()
	sealDir := util.Getenv(constants.SealDir, constants.SealDirDefault())
	sealer := seal.NewNoEnclaveSealer()
	recovery := recovery.NewSinglePartyRecovery()
	run(validator, issuer, sealDir, sealer, recovery)
}
