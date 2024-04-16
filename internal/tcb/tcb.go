// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tcb

import (
	"errors"
	"fmt"
	"slices"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/attestation/tcbstatus"
)

// Validity is the validity of a TCB level.
type Validity uint

const (
	// ValidityInvalid means the TCB level is invalid, but may have been accepted.
	ValidityInvalid Validity = iota
	// ValidityConditional means the TCB level may be considered valid (e.g., SWHardeningNeeded).
	ValidityConditional
	// ValidityUnconditional means the TCB level is valid unconditionally (e.g., UpToDate).
	ValidityUnconditional
)

// CheckStatus checks the TCB status and returns the validity of the TCB level.
// It returns an error if the TCB level is invalid and the status isn't accepted.
func CheckStatus(status tcbstatus.Status, tcbErr error, accepted []string) (Validity, error) {
	invalid := errors.Is(tcbErr, attestation.ErrTCBLevelInvalid)
	if !invalid {
		if tcbErr != nil {
			return ValidityInvalid, tcbErr
		}
		if status == tcbstatus.UpToDate {
			return ValidityUnconditional, nil
		}
		if status != tcbstatus.SWHardeningNeeded {
			return ValidityInvalid, fmt.Errorf("unexpected: got no error, but TCB status is %v", status)
		}
	} else if status == tcbstatus.UpToDate {
		return ValidityInvalid, fmt.Errorf("unexpected: TCB level invalid: %v", status)
	}
	if !slices.Contains(accepted, status.String()) {
		return ValidityInvalid, fmt.Errorf("TCB level invalid: %v", status)
	}
	if invalid {
		return ValidityInvalid, nil
	}
	return ValidityConditional, nil
}
