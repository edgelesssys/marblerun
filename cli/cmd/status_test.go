// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatus(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/status", r.RequestURI)

		resp := statusResponse{
			StatusCode:    1,
			StatusMessage: "Test Server waiting",
		}

		serverResp := server.GeneralResponse{
			Status: "success",
			Data:   resp,
		}

		assert.NoError(json.NewEncoder(w).Encode(serverResp))
	}))

	defer s.Close()

	err := cliStatus(host, []*pem.Block{cert})
	require.NoError(err)

	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	err = cliStatus(host, []*pem.Block{cert})
	require.Error(err)
}
