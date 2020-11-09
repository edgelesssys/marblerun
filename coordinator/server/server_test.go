// Copyright (c) Edgeless Systems GmbH.
// Licensed under the MIT License.

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/test"
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
	assert := assert.New(t)
	require := require.New(t)

	c := core.NewCoreWithMocks()
	mux := CreateServeMux(c)

	// set manifest
	req := httptest.NewRequest(http.MethodPost, "/manifest", strings.NewReader(test.ManifestJSONWithRecoveryKey))
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	require.Equal(http.StatusOK, resp.Code)

	// Check response format
	expectedRecoveryData := c.GetRecoveryData(context.TODO())
	assert.JSONEq(`{"EncryptionKey":"`+expectedRecoveryData+`"}`, resp.Body.String())

	// Decode JSON response from server
	var b64EncryptedRecoveryData recoveryData
	json.Unmarshal(resp.Body.Bytes(), &b64EncryptedRecoveryData)
	encryptedRecoveryData, err := base64.StdEncoding.DecodeString(b64EncryptedRecoveryData.EncryptionKey)
	require.NoError(err)

	// Decrypt recovery data and see if it matches the key used by the mock sealer
	block, _ := pem.Decode([]byte(test.RecoveryKeyPrivateKey))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(err)

	recoveryData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedRecoveryData, nil)
	require.EqualValues(recoveryData, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
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
