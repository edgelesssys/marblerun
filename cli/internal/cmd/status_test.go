// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatus(t *testing.T) {
	marshalMsg := func(msg statusResponse) []byte {
		bytes, err := json.Marshal(msg)
		require.NoError(t, err)
		return bytes
	}

	testCases := map[string]struct {
		getter  *stubGetter
		wantErr bool
	}{
		"recovery mode": {
			getter: &stubGetter{
				response: marshalMsg(
					statusResponse{
						StatusCode:    0,
						StatusMessage: "Recovery",
					},
				),
			},
		},
		"uninitialized": {
			getter: &stubGetter{
				response: marshalMsg(
					statusResponse{
						StatusCode:    1,
						StatusMessage: "Uninitialized",
					},
				),
			},
		},
		"waiting for manifest": {
			getter: &stubGetter{
				response: marshalMsg(
					statusResponse{
						StatusCode:    2,
						StatusMessage: "Waiting for manifest",
					},
				),
			},
		},
		"accepting marbles": {
			getter: &stubGetter{
				response: marshalMsg(
					statusResponse{
						StatusCode:    3,
						StatusMessage: "Accepting Marbles",
					},
				),
			},
		},
		"get error": {
			getter: &stubGetter{
				err: errors.New("failed"),
			},
			wantErr: true,
		},
		"unmarshal error": {
			getter: &stubGetter{
				response: []byte("invalid"),
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			cmd := &cobra.Command{}
			var out bytes.Buffer
			cmd.SetOut(&out)

			err := cliStatus(cmd, tc.getter)

			if tc.wantErr {
				assert.Error(err)
				return
			}

			assert.NoError(err)
			var expected statusResponse
			require.NoError(t, json.Unmarshal(tc.getter.response, &expected))
			assert.Contains(out.String(), expected.StatusMessage)
			assert.Equal(rest.StatusEndpoint, tc.getter.requestPath)
		})
	}
}
