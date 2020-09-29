package server

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/test"
	"github.com/stretchr/testify/assert"
)

func TestQuote(t *testing.T) {
	assert := assert.New(t)
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := core.NewMockSealer()
	c, err := core.NewCore("edgeless", []string{"localhost"}, validator, issuer, sealer)
	if err != nil {
		panic(err)
	}

	mux := CreateServeMux(c)

	req := httptest.NewRequest(http.MethodGet, "/quote", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)
	assert.Equal(http.StatusOK, w.Code)

}

func TestManifest(t *testing.T) {
	assert := assert.New(t)
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	tempDir, err := ioutil.TempDir("/tmp", "edg_coordinator_*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempDir)
	mockKey := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	sealer := core.NewAESGCMSealer(tempDir, mockKey)
	c, err := core.NewCore("edgeless", []string{"localhost"}, validator, issuer, sealer)
	if err != nil {
		panic(err)
	}

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
