// Copyright (c) Edgeless Systems GmbH.
// Licensed under the MIT License.

package server

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestQuote(t *testing.T) {
	zapLogger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	defer zapLogger.Sync()

	assert := assert.New(t)

	mux := CreateServeMux(core.NewCoreWithMocks(zapLogger))

	req := httptest.NewRequest(http.MethodGet, "/quote", nil)
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	assert.Equal(http.StatusOK, resp.Code)
}

func TestManifest(t *testing.T) {
	// setup mock zaplogger which can be passed to Core
	zapLogger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	defer zapLogger.Sync()

	assert := assert.New(t)
	require := require.New(t)

	c := core.NewCoreWithMocks(zapLogger)
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

func TestConcurrent(t *testing.T) {
	// This test is used to detect data races when run with -race
	zapLogger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	defer zapLogger.Sync()

	assert := assert.New(t)

	mux := CreateServeMux(core.NewCoreWithMocks(zapLogger))
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
