/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package tcb

import (
	"errors"
	"fmt"
	"slices"
	"strings"

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

// CheckAdvisories checks a list of Intel Security Advisories against a list of accepted advisories.
// It returns a list of not accepted advisories if the status is SWHardeningNeeded.
// If acceptedAdvisories is empty, all advisories are accepted and this function returns nil.
func CheckAdvisories(report attestation.Report, acceptedAdvisories []string) ([]string, error) {
	if report.TCBStatus != tcbstatus.SWHardeningNeeded || len(acceptedAdvisories) == 0 {
		return nil, nil
	}

	if report.TCBAdvisoriesErr != nil {
		return nil, fmt.Errorf("accepted advisory list not empty but report did not contain a valid advisory list: %w", report.TCBAdvisoriesErr)
	}

	var notAccepted []string
	for _, advisory := range report.TCBAdvisories {
		if !slices.ContainsFunc(acceptedAdvisories, func(other string) bool {
			return strings.EqualFold(advisory, other)
		}) {
			notAccepted = append(notAccepted, advisory)
		}
	}
	return notAccepted, nil
}
