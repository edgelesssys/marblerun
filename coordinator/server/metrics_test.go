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

	"github.com/edgelesssys/marblerun/coordinator/core"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestClientApiRequestMetrics(t *testing.T) {
	assert := assert.New(t)

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
	for testname, test := range tests {
		t.Logf("Subtest: %s", testname)

		reg := prometheus.NewRegistry()
		fac := promauto.With(reg)
		mux := CreateServeMux(core.NewCoreWithMocks(), &fac)

		metrics := mux.(*promServeMux).metrics[test.target]
		assert.Equal(0, promtest.CollectAndCount(metrics.reqest))
		assert.Equal(float64(0), promtest.ToFloat64(metrics.reqest.WithLabelValues(test.expectedStatusCode, strings.ToLower(test.method))))

		for i := 1; i < 6; i++ {
			req := httptest.NewRequest(test.method, test.target, nil)
			resp := httptest.NewRecorder()
			mux.ServeHTTP(resp, req)
			assert.Equal(1, promtest.CollectAndCount(metrics.reqest))
			assert.Equal(float64(i), promtest.ToFloat64(metrics.reqest.WithLabelValues(test.expectedStatusCode, strings.ToLower(test.method))))
		}
	}
}
