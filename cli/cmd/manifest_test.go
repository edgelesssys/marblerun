package cmd

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCliManifestGet(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/manifest", r.RequestURI)
		assert.Equal(http.MethodGet, r.Method)

		data := "Everything OK"

		serverResp := server.GeneralResponse{
			Status: "success",
			Data:   data,
		}

		assert.NoError(json.NewEncoder(w).Encode(serverResp))
	}))

	dir, err := ioutil.TempDir("", "unittest")
	require.NoError(err)

	defer os.RemoveAll(dir)
	defer s.Close()

	responseFile := filepath.Join(dir, "tmp-sign.json")
	err = cliManifestGet(responseFile, host, []*pem.Block{cert})
	require.NoError(err)
	response, err := ioutil.ReadFile(responseFile)
	require.NoError(err)
	require.Equal("Everything OK", string(response), "saved incorrect data to file")

	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	err = cliManifestGet(responseFile, host, []*pem.Block{cert})
	require.Error(err)
}

func TestCliManifestSet(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/manifest", r.RequestURI)
		assert.Equal(http.MethodPost, r.Method)

		reqData, err := ioutil.ReadAll(r.Body)
		assert.NoError(err)

		if string(reqData) == "00" {
			return
		}

		if string(reqData) == "11" {
			serverResp := server.GeneralResponse{
				Status: "success",
				Data:   "returned recovery secret",
			}
			assert.NoError(json.NewEncoder(w).Encode(serverResp))
			return
		}

		if string(reqData) == "22" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
	}))

	dir, err := ioutil.TempDir("", "unittest")
	require.NoError(err)

	defer os.RemoveAll(dir)
	defer s.Close()

	err = cliManifestSet([]byte("00"), host, []*pem.Block{cert}, "")
	require.NoError(err)

	err = cliManifestSet([]byte("11"), host, []*pem.Block{cert}, "")
	require.NoError(err)

	responseFile := filepath.Join(dir, "tmp-recovery.json")
	err = cliManifestSet([]byte("11"), host, []*pem.Block{cert}, responseFile)
	require.NoError(err)

	err = cliManifestSet([]byte("22"), host, []*pem.Block{cert}, "")
	require.Error(err)

	err = cliManifestSet([]byte("55"), host, []*pem.Block{cert}, "")
	require.Error(err)
}

func TestCliManifestUpdate(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/update", r.RequestURI)
		assert.Equal(http.MethodPost, r.Method)

		reqData, err := ioutil.ReadAll(r.Body)
		assert.NoError(err)

		if string(reqData) == "00" {
			return
		}

		if string(reqData) == "11" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if string(reqData) == "22" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer s.Close()

	clCert := tls.Certificate{}

	err := cliManifestUpdate([]byte("00"), host, clCert, []*pem.Block{cert})
	require.NoError(err)

	err = cliManifestUpdate([]byte("11"), host, clCert, []*pem.Block{cert})
	require.Error(err)

	err = cliManifestUpdate([]byte("22"), host, clCert, []*pem.Block{cert})
	require.Error(err)

	err = cliManifestUpdate([]byte("33"), host, clCert, []*pem.Block{cert})
	require.Error(err)
}
