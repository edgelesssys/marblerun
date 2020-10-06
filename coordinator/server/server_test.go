package server

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/test"
	"github.com/stretchr/testify/assert"
)

var manifest core.Manifest

func init() {
	if err := json.Unmarshal([]byte(test.ManifestJSON), &manifest); err != nil {
		log.Fatalln(err)
	}
}

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
	sealer := core.NewMockSealer()
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
