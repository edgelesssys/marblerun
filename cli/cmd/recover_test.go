package cmd

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCliRecover(t *testing.T) {
	require := require.New(t)
	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/recover" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)

		type recoveryStatusResp struct {
			StatusMessage string
		}

		data := recoveryStatusResp{
			StatusMessage: "Recovery successful.",
		}

		serverResp := testServerResponse{
			Status: "success",
			Data:   data,
		}

		if err := json.NewEncoder(w).Encode(serverResp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))

	defer s.Close()

	err := cliRecover(host, []byte{0xAA, 0xAA}, []*pem.Block{cert})
	require.NoError(err)

	// change handler func to request additional secrets
	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/recover" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		type recoveryStatusResp struct {
			StatusMessage string
		}

		data := recoveryStatusResp{
			StatusMessage: "Secret was processed successfully. Upload the next secret. Remaining secrets: 1",
		}

		serverResp := testServerResponse{
			Status: "success",
			Data:   data,
		}

		if err := json.NewEncoder(w).Encode(serverResp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	err = cliRecover(host, []byte{0xAA, 0xAA}, []*pem.Block{cert})
	require.NoError(err)
}
