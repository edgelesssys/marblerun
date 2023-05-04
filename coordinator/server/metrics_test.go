// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/clientapi"
	"github.com/edgelesssys/marblerun/coordinator/core"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestClientApiRequestMetrics(t *testing.T) {
	tests := map[string]struct {
		target             string
		method             string // use values from http package, like http.MethodGet
		expectedStatusCode string
	}{
		"getQuote": {
			target:             "/quote",
			method:             http.MethodGet,
			expectedStatusCode: "200",
		},
		"putQuote": {
			target:             "/quote",
			method:             http.MethodPut,
			expectedStatusCode: "405",
		},
		"getManifest": {
			target:             "/manifest",
			method:             http.MethodGet,
			expectedStatusCode: "200",
		},
		"postStatus": {
			target:             "/status",
			method:             http.MethodPost,
			expectedStatusCode: "405",
		},
		"getStatus": {
			target:             "/status",
			method:             http.MethodGet,
			expectedStatusCode: "200",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			reg := prometheus.NewRegistry()
			fac := promauto.With(reg)

			api := newTestClientAPI(t)
			mux := CreateServeMux(api, &fac)

			metrics := mux.(*promServeMux).metrics[tc.target]
			assert.Equal(0, promtest.CollectAndCount(metrics.request))
			assert.Equal(float64(0), promtest.ToFloat64(metrics.request.WithLabelValues(tc.expectedStatusCode, strings.ToLower(tc.method))))

			for i := 1; i < 6; i++ {
				req := httptest.NewRequest(tc.method, tc.target, nil)
				resp := httptest.NewRecorder()
				mux.ServeHTTP(resp, req)
				assert.Equal(1, promtest.CollectAndCount(metrics.request))
				assert.Equal(float64(i), promtest.ToFloat64(metrics.request.WithLabelValues(tc.expectedStatusCode, strings.ToLower(tc.method))))
			}
		})
	}
}

func newTestClientAPI(t *testing.T) *clientapi.ClientAPI {
	t.Helper()
	require := require.New(t)

	log, err := zap.NewDevelopment()
	require.NoError(err)
	defer log.Sync()

	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	store := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "")
	recovery := recovery.NewSinglePartyRecovery()
	core, err := core.NewCore([]string{"localhost"}, validator, issuer, store, recovery, log, nil, nil)
	require.NoError(err)

	api, err := clientapi.New(store, recovery, core, log)
	require.NoError(err)

	return api
}
