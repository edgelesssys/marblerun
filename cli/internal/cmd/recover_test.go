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

func TestCliRecover(t *testing.T) {
	testCases := map[string]struct {
		getter  *stubPoster
		wantErr bool
	}{
		"success": {
			getter: &stubPoster{
				response: func() []byte {
					resp := struct {
						StatusMessage string
					}{
						StatusMessage: "Success",
					}
					bytes, err := json.Marshal(resp)
					require.NoError(t, err)
					return bytes
				}(),
			},
		},
		"get error": {
			getter: &stubPoster{
				err: errors.New("failed"),
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

			err := cliRecover(cmd, []byte{0x00}, tc.getter)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Equal(tc.getter.requestPath, rest.RecoverEndpoint)
			assert.Equal(tc.getter.header, rest.ContentPlain)
			assert.Equal("Success\n", out.String())
		})
	}
}
