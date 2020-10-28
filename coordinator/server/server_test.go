package server

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/test"
	"github.com/stretchr/testify/assert"
)

func TestQuote(t *testing.T) {
	assert := assert.New(t)

	mux := CreateServeMux(core.NewCoreWithMocks())

	req := httptest.NewRequest(http.MethodGet, "/quote", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)
	assert.Equal(http.StatusOK, w.Code)

}

func TestManifest(t *testing.T) {
	assert := assert.New(t)

	c := core.NewCoreWithMocks()
	mux := CreateServeMux(c)

	//set manifest
	req := httptest.NewRequest(http.MethodPost, "/manifest", bytes.NewReader([]byte(test.ManifestJSON)))

	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)
	resp := w.Result()
	assert.Equal(http.StatusOK, resp.StatusCode)

	//get manifest signature
	req = httptest.NewRequest(http.MethodGet, "/manifest", nil)

	w = httptest.NewRecorder()

	mux.ServeHTTP(w, req)
	resp = w.Result()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	assert.Equal(http.StatusOK, resp.StatusCode)
	assert.Contains(string(b), "{\"ManifestSignature\":")

	//try set manifest again, should fail
	req = httptest.NewRequest(http.MethodPost, "/manifest", bytes.NewReader([]byte(test.ManifestJSON)))
	w = httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	resp = w.Result()

	b, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	assert.Equal(http.StatusBadRequest, resp.StatusCode)
	assert.Equal("server is not in expected state\n", string(b))
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
