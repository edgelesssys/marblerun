// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCliRecover(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/recover", r.RequestURI)
		assert.Equal(http.MethodPost, r.Method)

		reqData, err := ioutil.ReadAll(r.Body)
		assert.NoError(err)

		type recoveryStatusResp struct {
			StatusMessage string
		}

		if string(reqData) == "Return Error" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		data := recoveryStatusResp{
			StatusMessage: "Recovery successful.",
		}

		serverResp := server.GeneralResponse{
			Status: "success",
			Data:   data,
		}

		assert.NoError(json.NewEncoder(w).Encode(serverResp))
	}))

	defer s.Close()

	err := cliRecover(host, []byte{0xAA, 0xAA}, []*pem.Block{cert})
	require.NoError(err)

	err = cliRecover(host, []byte("Return Error"), []*pem.Block{cert})
	require.Error(err)
}
