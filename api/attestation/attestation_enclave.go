// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build marblerun_ego_enclave

package attestation

import (
	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/enclave"
)

// verifyRemoteReport uses EGo's enclave VerifyRemoteReport function to verify the remote report.
// This function can only be called from *inside* an EGo enclave.
func verifyRemoteReport(quote []byte) (attestation.Report, error) {
	return enclave.VerifyRemoteReport(quote)
}
