package cmd

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

type testServerResponse struct {
	Status  string      `json:"status"`
	Data    interface{} `json:"data"`
	Message string      `json:"message,omitempty"`
}

func newTestServer(handler http.Handler) (server *httptest.Server, addr string, cert *pem.Block) {
	s := httptest.NewTLSServer(handler)
	return s, s.Listener.Addr().String(), &pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}
}

func TestCliManifestGet(t *testing.T) {
	require := require.New(t)
	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/manifest" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		data := "Everything OK"

		serverResp := testServerResponse{
			Status: "success",
			Data:   data,
		}

		if err := json.NewEncoder(w).Encode(serverResp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))

	defer s.Close()
	responseFile := "test-tmp-sign.json"
	err := cliManifestGet(responseFile, host, []*pem.Block{cert})
	require.NoError(err)
	response, err := ioutil.ReadFile(responseFile)
	require.NoError(err)
	require.Equal("Everything OK", string(response), "saved incorrect data to file")

	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	err = cliManifestGet(responseFile, host, []*pem.Block{cert})
	require.Error(err)

	os.Remove(responseFile)
}

func TestCliManifestSet(t *testing.T) {
	require := require.New(t)
	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/manifest" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		reqData, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if string(reqData) == "00" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if string(reqData) == "11" {
			serverResp := testServerResponse{
				Status: "success",
				Data:   "returned recovery secret",
			}
			if err := json.NewEncoder(w).Encode(serverResp); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		if string(reqData) == "22" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer s.Close()

	err := cliManifestSet([]byte("00"), host, []*pem.Block{cert}, "")
	require.NoError(err)

	err = cliManifestSet([]byte("11"), host, []*pem.Block{cert}, "")
	require.NoError(err)

	responseFile := "test-tmp-recovery.json"
	err = cliManifestSet([]byte("11"), host, []*pem.Block{cert}, responseFile)
	require.NoError(err)
	err = os.Remove(responseFile)
	require.NoError(err)

	err = cliManifestSet([]byte("22"), host, []*pem.Block{cert}, "")
	require.Error(err)

	err = cliManifestSet([]byte("55"), host, []*pem.Block{cert}, "")
	require.Error(err)
}

func TestCliManifestUpdate(t *testing.T) {
	require := require.New(t)
	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/update" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		reqData, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if string(reqData) == "00" {
			w.WriteHeader(http.StatusOK)
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
