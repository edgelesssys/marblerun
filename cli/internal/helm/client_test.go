// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package helm

import (
	"testing"

	"github.com/edgelesssys/marblerun/util"
	"github.com/stretchr/testify/assert"
)

func TestNeedsDeletion(t *testing.T) {
	testCases := map[string]struct {
		existingKey  string
		sgxKey       string
		wantDeletion bool
	}{
		"intel key with azure plugin": {
			existingKey:  util.IntelEpc.String(),
			sgxKey:       util.AzureEpc.String(),
			wantDeletion: true,
		},
		"intel key with alibaba plugin": {
			existingKey:  util.IntelEpc.String(),
			sgxKey:       util.AlibabaEpc.String(),
			wantDeletion: true,
		},
		"azure key with intel plugin": {
			existingKey:  util.AzureEpc.String(),
			sgxKey:       util.IntelEpc.String(),
			wantDeletion: true,
		},
		"azure key with alibaba plugin": {
			existingKey:  util.AzureEpc.String(),
			sgxKey:       util.AlibabaEpc.String(),
			wantDeletion: true,
		},
		"alibaba key with intel plugin": {
			existingKey:  util.AlibabaEpc.String(),
			sgxKey:       util.IntelEpc.String(),
			wantDeletion: true,
		},
		"alibaba key with azure plugin": {
			existingKey:  util.AlibabaEpc.String(),
			sgxKey:       util.AzureEpc.String(),
			wantDeletion: true,
		},
		"same key": {
			existingKey:  util.IntelEpc.String(),
			sgxKey:       util.IntelEpc.String(),
			wantDeletion: false,
		},
		"intel provision with intel plugin": {
			existingKey:  util.IntelProvision.String(),
			sgxKey:       util.IntelEpc.String(),
			wantDeletion: false,
		},
		"intel enclave with intel plugin": {
			existingKey:  util.IntelEnclave.String(),
			sgxKey:       util.IntelEpc.String(),
			wantDeletion: false,
		},
		"regular resource with intel plugin": {
			existingKey:  "cpu",
			sgxKey:       util.IntelEpc.String(),
			wantDeletion: false,
		},
		"custom resource with intel plugin": {
			existingKey:  "custom-sgx-resource",
			sgxKey:       util.IntelEpc.String(),
			wantDeletion: false,
		},
		"intel provision with custom plugin": {
			existingKey:  util.IntelProvision.String(),
			sgxKey:       "custom-sgx-resource",
			wantDeletion: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			delete := needsDeletion(tc.existingKey, tc.sgxKey)
			assert.Equal(tc.wantDeletion, delete)
		})
	}
}
