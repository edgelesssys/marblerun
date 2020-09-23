package server

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/stretchr/testify/assert"
)

const manifestJSON string = `{
	"Packages": {
		"backend": {
			"UniqueID": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],
			"Debug": false
		},
		"frontend": {
			"SignerID": [31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0],
			"ProductID": [44],
			"SecurityVersion": 3,
			"Debug": true
		}
	},
	"Infrastructures": {
		"Azure": {
			"QESVN": 2,
			"PCESVN": 3,
			"CPUSVN": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
			"RootCA": [3,3,3]
		},
		"Alibaba": {
			"QESVN": 2,
			"PCESVN": 4,
			"CPUSVN": [15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0],
			"RootCA": [4,4,4]
		}
	},
	"Marbles": {
		"backend_first": {
			"Package": "backend",
			"MaxActivations": 1,
			"Parameters": {
				"Files": {
					"/abc/defg.txt": "foo",
					"/ghi/jkl.mno": "bar"
				},
				"Env": {
					"IS_FIRST": "true",
					"ROOT_CA": "$$root_ca",
					"SEAL_KEY": "$$seal_key",
					"MARBLE_CERT": "$$marble_cert",
					"MARBLE_KEY": "$$marble_key"
				},
				"Argv": [
					"--first",
					"serve"
				]
			}
		},
		"backend_other": {
			"Package": "backend",
			"Parameters": {
				"Env": {
					"ROOT_CA": "$$root_ca",
					"SEAL_KEY": "$$seal_key",
					"MARBLE_CERT": "$$marble_cert",
					"MARBLE_KEY": "$$marble_key"
				},
				"Argv": [
					"serve"
				]
			}
		},
		"frontend": {
			"Package": "frontend",
			"Parameters": {
				"Env": {
					"ROOT_CA": "$$root_ca",
					"SEAL_KEY": "$$seal_key",
					"MARBLE_CERT": "$$marble_cert",
					"MARBLE_KEY": "$$marble_key"
				}
			}
		}
	},
	"Clients": {
		"owner": [9,9,9]
	}
}`

func TestQuote(t *testing.T) {
	assert := assert.New(t)
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	c, err := core.NewCore("edgeless", validator, issuer)
	if err != nil {
		panic(err)
	}

	mux := CreateServeMux(c)

	req := httptest.NewRequest(http.MethodGet, "/quote", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)
	resp := w.Result()
	assert.Equal(http.StatusOK, resp.StatusCode)

}

func TestManifest(t *testing.T) {
	assert := assert.New(t)
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	c, err := core.NewCore("edgeless", validator, issuer)
	if err != nil {
		panic(err)
	}

	mux := CreateServeMux(c)

	//set manifest
	manifestReq := SetManifestRequest{
		Manifest: []byte(manifestJSON),
	}
	manifestReqRaw, err := json.Marshal(manifestReq)
	if err != nil {
		panic(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/manifest", bytes.NewReader(manifestReqRaw))

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
	req = httptest.NewRequest(http.MethodPost, "/manifest", bytes.NewReader(manifestReqRaw))
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
