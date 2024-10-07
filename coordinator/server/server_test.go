// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/server/handler"
	v1 "github.com/edgelesssys/marblerun/coordinator/server/v1"
	"github.com/edgelesssys/marblerun/test"
	"github.com/edgelesssys/marblerun/util"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"go.uber.org/zap/zaptest"
)

func TestQuote(t *testing.T) {
	assert := assert.New(t)

	mux := CreateServeMux(newTestClientAPI(t), nil, zaptest.NewLogger(t))

	req := httptest.NewRequest(http.MethodGet, "/quote", nil)
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	assert.Equal(http.StatusOK, resp.Code)
}

func TestManifest(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	c := newTestClientAPI(t)
	mux := CreateServeMux(c, nil, zaptest.NewLogger(t))

	// set manifest
	req := httptest.NewRequest(http.MethodPost, "/manifest", strings.NewReader(test.ManifestJSON))
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	require.Equal(http.StatusOK, resp.Code)

	// get manifest signature
	req = httptest.NewRequest(http.MethodGet, "/manifest", nil)
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	require.Equal(http.StatusOK, resp.Code)

	sigRootECDSA, manifest, err := c.GetManifestSignature(context.Background())
	require.NoError(err)
	fingerprint := sha256.Sum256(manifest)
	assert.JSONEq(`{"status":"success","data":{"ManifestSignatureRootECDSA":"`+base64.StdEncoding.EncodeToString(sigRootECDSA)+`","ManifestSignature":"`+hex.EncodeToString(fingerprint[:])+`","Manifest":"`+base64.StdEncoding.EncodeToString(manifest)+`"}}`, resp.Body.String())

	// try setting manifest again, should fail
	req = httptest.NewRequest(http.MethodPost, "/manifest", strings.NewReader(test.ManifestJSON))
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	require.Equal(http.StatusBadRequest, resp.Code)
}

func TestManifestWithRecoveryKey(t *testing.T) {
	require := require.New(t)

	c := newTestClientAPI(t)
	mux := CreateServeMux(c, nil, zaptest.NewLogger(t))

	// set manifest
	req := httptest.NewRequest(http.MethodPost, "/manifest", strings.NewReader(test.ManifestJSONWithRecoveryKey))
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	require.Equal(http.StatusOK, resp.Code)

	// Decode JSON response from server
	var encryptedRecoveryData v1.RecoveryDataResponse
	b64EncryptedRecoveryDataJSON := gjson.Get(resp.Body.String(), "data")
	require.NoError(json.Unmarshal([]byte(b64EncryptedRecoveryDataJSON.String()), &encryptedRecoveryData))

	for _, encryptedRecoveryData := range encryptedRecoveryData.RecoverySecrets {
		// Decrypt recovery data and see if it matches the key used by the mock sealer
		recoveryData, err := util.DecryptOAEP(test.RecoveryPrivateKey, encryptedRecoveryData)
		require.NoError(err)
		require.NotNil(recoveryData)
	}
}

func TestGetUpdateLog(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Setup mock core and set a manifest
	c := newTestClientAPI(t)
	_, err := c.SetManifest(context.Background(), []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)
	mux := CreateServeMux(c, nil, zaptest.NewLogger(t))

	req := httptest.NewRequest(http.MethodGet, "/update", nil)
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	assert.Equal(http.StatusOK, resp.Code)
	assert.EqualValues('{', resp.Body.String()[0])
}

func TestMonotonicCounter(t *testing.T) {
	testCases := map[string]struct {
		api          stubAPI
		req          string
		wantStatus   int
		wantOldValue uint64
		wantID       string
		wantNewValue uint64
	}{
		"success": {
			api:          stubAPI{featureEnabledResult: true},
			req:          `{"name":"foo","value":3}`,
			wantStatus:   http.StatusOK,
			wantOldValue: 2,
			wantID:       "type:02030400-0000-0000-0000-000000000000:foo",
			wantNewValue: 3,
		},
		"bad request": {
			api:        stubAPI{featureEnabledResult: true},
			req:        "bad",
			wantStatus: http.StatusBadRequest,
		},
		"feature not enabled": {
			api:        stubAPI{featureEnabledResult: false},
			req:        `{"name":"foo","value":3}`,
			wantStatus: http.StatusForbidden,
		},
		"VerifyMarble error": {
			api:        stubAPI{featureEnabledResult: true, verifyMarbleErr: assert.AnError},
			req:        `{"name":"foo","value":3}`,
			wantStatus: http.StatusUnauthorized,
		},
		"SetMonotonicCounter error": {
			api:        stubAPI{featureEnabledResult: true, setMonotonicCounterErr: assert.AnError},
			req:        `{"name":"foo","value":3}`,
			wantStatus: http.StatusInternalServerError,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			mux := CreateServeMux(&tc.api, nil, nil)

			req := httptest.NewRequest(http.MethodPost, "/api/v2/monotonic-counter", strings.NewReader(tc.req))
			req.TLS = &tls.ConnectionState{}

			resp := httptest.NewRecorder()
			mux.ServeHTTP(resp, req)

			assert.Equal(tc.wantStatus, resp.Code)
			assert.Equal(tc.wantOldValue, gjson.Get(resp.Body.String(), "data.value").Uint())
			assert.Equal(tc.wantID, tc.api.setMonotonicCounterID)
			assert.Equal(tc.wantNewValue, tc.api.setMonotonicCounterValue)
		})
	}
}

func TestUpdate(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Setup mock core and set a manifest
	c := newTestClientAPI(t)
	_, err := c.SetManifest(context.Background(), []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)
	mux := CreateServeMux(c, nil, zaptest.NewLogger(t))

	// Make HTTP update request with no TLS at all, should be unauthenticated
	req := httptest.NewRequest(http.MethodPost, "/update", strings.NewReader(test.UpdateManifest))
	resp := httptest.NewRecorder()
	err = testRequestWithCert(req, resp, mux)
	assert.NoError(err)
}

func TestReadSecret(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Setup mock core and set a manifest
	c := newTestClientAPI(t)
	_, err := c.SetManifest(context.Background(), []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)
	mux := CreateServeMux(c, nil, zaptest.NewLogger(t))

	// Make HTTP secret request with no TLS at all, should be unauthenticated
	req := httptest.NewRequest(http.MethodGet, "/secrets?s=symmetricKeyShared", nil)
	resp := httptest.NewRecorder()
	err = testRequestWithCert(req, resp, mux)
	assert.NoError(err)
}

func TestSetSecret(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Setup mock core and set a manifest
	c := newTestClientAPI(t)
	_, err := c.SetManifest(context.Background(), []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)
	mux := CreateServeMux(c, nil, zaptest.NewLogger(t))

	// Make HTTP secret request with no TLS at all, should be unauthenticated
	req := httptest.NewRequest(http.MethodPost, "/secrets", strings.NewReader(test.UserSecrets))
	resp := httptest.NewRecorder()
	err = testRequestWithCert(req, resp, mux)
	assert.NoError(err)
}

func testRequestWithCert(req *http.Request, resp *httptest.ResponseRecorder, mux serveMux) error {
	mux.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		return errors.New("request without certificate was not rejected")
	}

	// Get certificates to test
	adminTestCert, otherTestCert := test.MustSetupTestCerts(test.RecoveryPrivateKey)
	adminTestCertSlice := []*x509.Certificate{adminTestCert}
	otherTestCertSlice := []*x509.Certificate{otherTestCert}

	// Create mock TLS object and with wrong certificate, should fail
	req.TLS = &tls.ConnectionState{}
	req.TLS.PeerCertificates = otherTestCertSlice
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		return errors.New("request with wrong certificate was not rejected")
	}

	// Create mock TLS connection with right certificate, should pass
	req.TLS.PeerCertificates = adminTestCertSlice
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		return errors.New("correct request was not accepted")
	}
	return nil
}

func TestConcurrent(t *testing.T) {
	// This test is used to detect data races when run with -race

	assert := assert.New(t)

	mux := CreateServeMux(newTestClientAPI(t), nil, zaptest.NewLogger(t))
	var wg sync.WaitGroup

	getQuote := func() {
		req := httptest.NewRequest(http.MethodGet, "/quote", nil)
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, req)
		assert.Equal(http.StatusOK, resp.Code)
		wg.Done()
	}

	getManifest := func() {
		req := httptest.NewRequest(http.MethodGet, "/manifest", nil)
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, req)
		assert.Equal(http.StatusOK, resp.Code)
		wg.Done()
	}

	postManifest := func() {
		req := httptest.NewRequest(http.MethodPost, "/manifest", strings.NewReader(test.ManifestJSON))
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, req)
		wg.Done()
	}

	wg.Add(6)
	go getQuote()
	go getQuote()
	go getManifest()
	go getManifest()
	go postManifest()
	go postManifest()
	wg.Wait()
}

type stubAPI struct {
	handler.ClientAPI

	featureEnabledResult   bool
	verifyMarbleErr        error
	setMonotonicCounterErr error

	featureEnabledFeature    string
	setMonotonicCounterID    string
	setMonotonicCounterValue uint64
}

func (a *stubAPI) FeatureEnabled(_ context.Context, feature string) bool {
	a.featureEnabledFeature = feature
	return a.featureEnabledResult
}

func (a *stubAPI) VerifyMarble(_ context.Context, _ []*x509.Certificate) (string, uuid.UUID, error) {
	return "type", uuid.UUID{2, 3, 4}, a.verifyMarbleErr
}

func (a *stubAPI) SetMonotonicCounter(_ context.Context, marbleType string, marbleUUID uuid.UUID, name string, value uint64) (uint64, error) {
	if a.setMonotonicCounterErr != nil {
		return 0, a.setMonotonicCounterErr
	}
	a.setMonotonicCounterID = fmt.Sprintf("%v:%v:%v", marbleType, marbleUUID, name)
	a.setMonotonicCounterValue = value
	return 2, nil
}
