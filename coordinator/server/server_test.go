// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/core"
	"github.com/edgelesssys/marblerun/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuote(t *testing.T) {
	assert := assert.New(t)

	mux := CreateServeMux(core.NewCoreWithMocks())

	req := httptest.NewRequest(http.MethodGet, "/quote", nil)
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	assert.Equal(http.StatusOK, resp.Code)
}

func TestManifest(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	c := core.NewCoreWithMocks()
	mux := CreateServeMux(c)

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

	sig := hex.EncodeToString(c.GetManifestSignature(context.TODO()))
	assert.JSONEq(`{"ManifestSignature":"`+sig+`"}`, resp.Body.String())

	// try setting manifest again, should fail
	req = httptest.NewRequest(http.MethodPost, "/manifest", strings.NewReader(test.ManifestJSON))
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	require.Equal(http.StatusBadRequest, resp.Code)
}

func TestManifestWithRecoveryKey(t *testing.T) {
	require := require.New(t)

	c := core.NewCoreWithMocks()
	mux := CreateServeMux(c)

	// set manifest
	req := httptest.NewRequest(http.MethodPost, "/manifest", strings.NewReader(test.ManifestJSONWithRecoveryKey))
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	require.Equal(http.StatusOK, resp.Code)

	// Decode JSON response from server
	var b64EncryptedRecoveryData recoveryDataResp
	require.NoError(json.Unmarshal(resp.Body.Bytes(), &b64EncryptedRecoveryData))
	encryptedRecoveryData, err := base64.StdEncoding.DecodeString(b64EncryptedRecoveryData.EncryptionKey)
	require.NoError(err)

	// Decrypt recovery data and see if it matches the key used by the mock sealer
	recoveryData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, test.RecoveryPrivateKey, encryptedRecoveryData, nil)
	require.NoError(err)
	require.NotNil(recoveryData)
}

func TestUpdate(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Setup mock core and set a manifest
	c := core.NewCoreWithMocks()
	_, err := c.SetManifest(context.TODO(), []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)
	mux := CreateServeMux(c)

	// Make HTTP update request with no TLS at all, should be unauthenticated
	req := httptest.NewRequest(http.MethodPost, "/update", strings.NewReader(test.UpdateManifest))
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	assert.Equal(http.StatusUnauthorized, resp.Code)

	// Get certificates to test
	adminTestCert, otherTestCert := test.MustSetupTestCerts(test.RecoveryPrivateKey)
	adminTestCertSlice := []*x509.Certificate{adminTestCert}
	otherTestCertSlice := []*x509.Certificate{otherTestCert}

	// Create mock TLS object and with wrong certificate, should fail
	req.TLS = &tls.ConnectionState{}
	req.TLS.PeerCertificates = otherTestCertSlice
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	assert.Equal(http.StatusUnauthorized, resp.Code)

	// Create mock TLS connection with right certificate, should pass
	req.TLS.PeerCertificates = adminTestCertSlice
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	assert.Equal(http.StatusOK, resp.Code)
}

func TestConcurrent(t *testing.T) {
	// This test is used to detect data races when run with -race

	assert := assert.New(t)

	mux := CreateServeMux(core.NewCoreWithMocks())
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
