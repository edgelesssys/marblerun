// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tcb

import (
	"errors"
	"fmt"
	"testing"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckStatus(t *testing.T) {
	otherErr := errors.New("failed")

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
			tcbErr:   otherErr,
			accepted: []string{},
			wantErr:  true,
		},
		{
			status:   tcbstatus.OutOfDate,
			tcbErr:   otherErr,
			accepted: []string{},
			wantErr:  true,
		},
		{
			status:   tcbstatus.SWHardeningNeeded,
			tcbErr:   otherErr,
			accepted: []string{},
			wantErr:  true,
		},
		// unexpected error can't be accepted
		{
			status:   tcbstatus.UpToDate,
			tcbErr:   otherErr,
			accepted: []string{"UpToDate", "OutOfDate", "SWHardeningNeeded"},
			wantErr:  true,
		},
		{
			status:   tcbstatus.OutOfDate,
			tcbErr:   otherErr,
			accepted: []string{"UpToDate", "OutOfDate", "SWHardeningNeeded"},
			wantErr:  true,
		},
		{
			status:   tcbstatus.SWHardeningNeeded,
			tcbErr:   otherErr,
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
