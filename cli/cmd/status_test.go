package cmd

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStatus(t *testing.T) {
	require := require.New(t)

	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/status" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		resp := statusResponse{
			StatusCode:    1,
			StatusMessage: "Test Server waiting",
		}

		serverResp := testServerResponse{
			Status: "success",
			Data:   resp,
		}

		if err := json.NewEncoder(w).Encode(serverResp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))

	defer s.Close()

	err := cliStatus(host, []*pem.Block{cert})
	require.NoError(err)

	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	err = cliStatus(host, []*pem.Block{cert})
	require.Error(err)
}
