// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package helm

import (
	"encoding/base64"
	"testing"

	"github.com/edgelesssys/marblerun/util/k8sutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNeedsDeletion(t *testing.T) {
	testCases := map[string]struct {
		existingKey  string
		sgxKey       string
		wantDeletion bool
	}{
		"intel key with azure plugin": {
			existingKey:  k8sutil.IntelEpc.String(),
			sgxKey:       k8sutil.AzureEpc.String(),
			wantDeletion: true,
		},
		"intel key with alibaba plugin": {
			existingKey:  k8sutil.IntelEpc.String(),
			sgxKey:       k8sutil.AlibabaEpc.String(),
			wantDeletion: true,
		},
		"azure key with intel plugin": {
			existingKey:  k8sutil.AzureEpc.String(),
			sgxKey:       k8sutil.IntelEpc.String(),
			wantDeletion: true,
		},
		"azure key with alibaba plugin": {
			existingKey:  k8sutil.AzureEpc.String(),
			sgxKey:       k8sutil.AlibabaEpc.String(),
			wantDeletion: true,
		},
		"alibaba key with intel plugin": {
			existingKey:  k8sutil.AlibabaEpc.String(),
			sgxKey:       k8sutil.IntelEpc.String(),
			wantDeletion: true,
		},
		"alibaba key with azure plugin": {
			existingKey:  k8sutil.AlibabaEpc.String(),
			sgxKey:       k8sutil.AzureEpc.String(),
			wantDeletion: true,
		},
		"same key": {
			existingKey:  k8sutil.IntelEpc.String(),
			sgxKey:       k8sutil.IntelEpc.String(),
			wantDeletion: false,
		},
		"intel provision with intel plugin": {
			existingKey:  k8sutil.IntelProvision.String(),
			sgxKey:       k8sutil.IntelEpc.String(),
			wantDeletion: false,
		},
		"intel enclave with intel plugin": {
			existingKey:  k8sutil.IntelEnclave.String(),
			sgxKey:       k8sutil.IntelEpc.String(),
			wantDeletion: false,
		},
		"regular resource with intel plugin": {
			existingKey:  "cpu",
			sgxKey:       k8sutil.IntelEpc.String(),
			wantDeletion: false,
		},
		"custom resource with intel plugin": {
			existingKey:  "custom-sgx-resource",
			sgxKey:       k8sutil.IntelEpc.String(),
			wantDeletion: false,
		},
		"intel provision with custom plugin": {
			existingKey:  k8sutil.IntelProvision.String(),
			sgxKey:       "custom-sgx-resource",
			wantDeletion: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.wantDeletion, needsDeletion(tc.existingKey, tc.sgxKey))
		})
	}
}

func TestUpdateValues(t *testing.T) {
	testCases := map[string]struct {
		opts      Options
		chartVals map[string]interface{}
		wantVals  func(*testing.T, map[string]interface{})
		wantErr   bool
	}{
		"github PAT gets encoded": {
			opts: Options{
				SimulationMode: true,
				AccessToken:    "ghp_foo",
			},
			chartVals: map[string]interface{}{
				"coordinator": map[string]interface{}{
					"repository": "myrepo",
				},
			},
			wantVals: func(t *testing.T, vals map[string]interface{}) {
				assert := assert.New(t)
				require := require.New(t)
				pullSecret, err := base64.StdEncoding.DecodeString(vals["pullSecret"].(map[string]interface{})["token"].(string))
				require.NoError(err)
				assert.EqualValues(`{"auths":{"myrepo":{"auth":"Z2hwX2ZvbzpnaHBfZm9v"}}}`, pullSecret)
			},
		},
		"other token is taken unmodified": {
			opts: Options{
				SimulationMode: true,
				AccessToken:    "foo",
			},
			chartVals: map[string]interface{}{
				"coordinator": map[string]interface{}{
					"repository": "myrepo",
				},
			},
			wantVals: func(t *testing.T, vals map[string]interface{}) {
				assert := assert.New(t)
				require := require.New(t)
				pullSecret, err := base64.StdEncoding.DecodeString(vals["pullSecret"].(map[string]interface{})["token"].(string))
				require.NoError(err)
				assert.EqualValues(`{"auths":{"myrepo":{"auth":"foo"}}}`, pullSecret)
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			gotVals, err := UpdateValues(tc.opts, tc.chartVals)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)

			tc.wantVals(t, gotVals)
		})
	}
}
