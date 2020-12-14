// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// +build enclave

package main

import (
	"path/filepath"

	"github.com/edgelesssys/marblerun/coordinator/quote/ertvalidator"
)

func main() {
	validator := ertvalidator.NewERTValidator()
	issuer := ertvalidator.NewERTIssuer()
	sealDirPrefix := filepath.Join(filepath.FromSlash("/edg"), "hostfs")
	run(validator, issuer, sealDirPrefix)
}
