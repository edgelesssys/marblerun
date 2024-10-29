/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package tcb

import (
	"fmt"
	"testing"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckStatus(t *testing.T) {
	testCases := []struct {
		status       tcbstatus.Status
		tcbErr       error
		accepted     []string
		wantErr      bool
		wantValidity Validity
	}{
		// all combinations of status{UpToDate,OutOfDate,SWHardeningNeeded} and tcbErr{nil,invalid,other} for empty accepted
		{
			status:       tcbstatus.UpToDate,
			tcbErr:       nil,
			accepted:     []string{},
			wantValidity: ValidityUnconditional,
		},
		{
			status:   tcbstatus.OutOfDate,
			tcbErr:   nil,
			accepted: []string{},
			wantErr:  true,
		},
		{
			status:   tcbstatus.SWHardeningNeeded,
			tcbErr:   nil,
			accepted: []string{},
			wantErr:  true,
		},
		{
			status:   tcbstatus.UpToDate,
			tcbErr:   attestation.ErrTCBLevelInvalid,
			accepted: []string{},
			wantErr:  true,
		},
		{
			status:   tcbstatus.OutOfDate,
			tcbErr:   attestation.ErrTCBLevelInvalid,
			accepted: []string{},
			wantErr:  true,
		},
		{
			status:   tcbstatus.SWHardeningNeeded,
			tcbErr:   attestation.ErrTCBLevelInvalid,
			accepted: []string{},
			wantErr:  true,
		},
		{
			status:   tcbstatus.UpToDate,
			tcbErr:   assert.AnError,
			accepted: []string{},
			wantErr:  true,
		},
		{
			status:   tcbstatus.OutOfDate,
			tcbErr:   assert.AnError,
			accepted: []string{},
			wantErr:  true,
		},
		{
			status:   tcbstatus.SWHardeningNeeded,
			tcbErr:   assert.AnError,
			accepted: []string{},
			wantErr:  true,
		},
		// unexpected error can't be accepted
		{
			status:   tcbstatus.UpToDate,
			tcbErr:   assert.AnError,
			accepted: []string{"UpToDate", "OutOfDate", "SWHardeningNeeded"},
			wantErr:  true,
		},
		{
			status:   tcbstatus.OutOfDate,
			tcbErr:   assert.AnError,
			accepted: []string{"UpToDate", "OutOfDate", "SWHardeningNeeded"},
			wantErr:  true,
		},
		{
			status:   tcbstatus.SWHardeningNeeded,
			tcbErr:   assert.AnError,
			accepted: []string{"UpToDate", "OutOfDate", "SWHardeningNeeded"},
			wantErr:  true,
		},
		// unexpected combination of tcbStatus and tcbErr can't be accepted
		{
			status:   tcbstatus.OutOfDate,
			tcbErr:   nil,
			accepted: []string{"UpToDate", "OutOfDate", "SWHardeningNeeded"},
			wantErr:  true,
		},
		{
			status:   tcbstatus.UpToDate,
			tcbErr:   attestation.ErrTCBLevelInvalid,
			accepted: []string{"UpToDate", "OutOfDate", "SWHardeningNeeded"},
			wantErr:  true,
		},
		// statuses can be accepted
		{
			status:       tcbstatus.SWHardeningNeeded,
			tcbErr:       nil,
			accepted:     []string{"SWHardeningNeeded"},
			wantValidity: ValidityConditional,
		},
		{
			status:       tcbstatus.OutOfDate,
			tcbErr:       attestation.ErrTCBLevelInvalid,
			accepted:     []string{"OutOfDate"},
			wantValidity: ValidityInvalid,
		},
		{
			status:       tcbstatus.SWHardeningNeeded,
			tcbErr:       attestation.ErrTCBLevelInvalid,
			accepted:     []string{"SWHardeningNeeded"},
			wantValidity: ValidityInvalid,
		},
		// only UpToDate is implicitly accepted
		{
			status:       tcbstatus.UpToDate,
			tcbErr:       nil,
			accepted:     []string{"OutOfDate", "SWHardeningNeeded"},
			wantValidity: ValidityUnconditional,
		},
		{
			status:   tcbstatus.SWHardeningNeeded,
			tcbErr:   nil,
			accepted: []string{"UpToDate", "OutOfDate"},
			wantErr:  true,
		},
		{
			status:   tcbstatus.OutOfDate,
			tcbErr:   attestation.ErrTCBLevelInvalid,
			accepted: []string{"UpToDate", "SWHardeningNeeded"},
			wantErr:  true,
		},
		{
			status:   tcbstatus.SWHardeningNeeded,
			tcbErr:   attestation.ErrTCBLevelInvalid,
			accepted: []string{"UpToDate", "OutOfDate"},
			wantErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%v %v %v", tc.status, tc.tcbErr, tc.accepted), func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			validity, err := CheckStatus(tc.status, tc.tcbErr, tc.accepted)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)

			assert.Equal(tc.wantValidity, validity)
		})
	}
}

func TestCheckAdvisories(t *testing.T) {
	testCases := map[string]struct {
		status             tcbstatus.Status
		advisories         []string
		acceptedAdvisories []string
		advisoriesErr      error
		wantNotAccepted    []string
		wantErr            bool
	}{
		"empty accepted list accepts all advisories": {
			status:             tcbstatus.SWHardeningNeeded,
			advisories:         []string{"INTEL-SA-0001", "INTEL-SA-0002"},
			acceptedAdvisories: []string{},
			wantNotAccepted:    nil,
		},
		"missing accepted advisories": {
			status:             tcbstatus.SWHardeningNeeded,
			advisories:         []string{"INTEL-SA-0001", "INTEL-SA-0002"},
			acceptedAdvisories: []string{"INTEL-SA-0003"},
			wantNotAccepted:    []string{"INTEL-SA-0001", "INTEL-SA-0002"},
		},
		"all advisories accepted": {
			status:             tcbstatus.SWHardeningNeeded,
			advisories:         []string{"INTEL-SA-0001", "INTEL-SA-0002"},
			acceptedAdvisories: []string{"INTEL-SA-0001", "INTEL-SA-0002"},
			wantNotAccepted:    nil,
		},
		"some advisories accepted": {
			status:             tcbstatus.SWHardeningNeeded,
			advisories:         []string{"INTEL-SA-0001", "INTEL-SA-0002"},
			acceptedAdvisories: []string{"INTEL-SA-0001"},
			wantNotAccepted:    []string{"INTEL-SA-0002"},
		},
		"other status than SWHardeningNeeded": {
			status:             tcbstatus.ConfigurationAndSWHardeningNeeded,
			advisories:         []string{"INTEL-SA-0001", "INTEL-SA-0002"},
			acceptedAdvisories: []string{"INTEL-SA-0001"},
			wantNotAccepted:    nil,
		},
		"TCBAdvisoriesErr causes an error": {
			status:             tcbstatus.SWHardeningNeeded,
			acceptedAdvisories: []string{"INTEL-SA-0001"},
			advisoriesErr:      assert.AnError,
			wantErr:            true,
		},
		"TCBAdvisoriesErr is ignored if all advisories are accepted": {
			status:        tcbstatus.SWHardeningNeeded,
			advisoriesErr: assert.AnError,
		},
		"TCBAdvisoriesErr is ignored on other status": {
			status:        tcbstatus.UpToDate,
			advisoriesErr: assert.AnError,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			report := attestation.Report{
				TCBStatus:        tc.status,
				TCBAdvisories:    tc.advisories,
				TCBAdvisoriesErr: tc.advisoriesErr,
			}

			notAccepted, err := CheckAdvisories(report, tc.acceptedAdvisories)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Equal(tc.wantNotAccepted, notAccepted)
		})
	}
}
