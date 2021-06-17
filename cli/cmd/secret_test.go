package cmd

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/server"
	"github.com/stretchr/testify/assert"
)

func TestSetSecrets(t *testing.T) {
	assert := assert.New(t)
	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/secrets", r.RequestURI)
		assert.Equal(http.MethodPost, r.Method)
		request, err := ioutil.ReadAll(r.Body)
		assert.NoError(err)

		if strings.Contains(string(request), "restricted_secret") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if strings.Contains(string(request), `"Type":"invalid"`) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		serverResp := server.GeneralResponse{
			Status: "success",
		}
		assert.NoError(json.NewEncoder(w).Encode(serverResp))
	}))
	defer s.Close()

	err := cliSecretSet(host, []byte(`{"user_secret":{"Type":"plain","Key":"Q0xJIFRlc3QK"}}`), tls.Certificate{}, []*pem.Block{cert})
	assert.NoError(err)

	err = cliSecretSet(host, []byte(`{"restricted_secret":{"Type":"plain","Key":"Q0xJIFRlc3QK"}}`), tls.Certificate{}, []*pem.Block{cert})
	assert.Error(err)

	err = cliSecretSet(host, []byte(`{"user_secret":{"Type":"invalid","Key":"Q0xJIFRlc3QK"}}`), tls.Certificate{}, []*pem.Block{cert})
	assert.Error(err)
}

func TestGetSecrets(t *testing.T) {
	assert := assert.New(t)
	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(http.MethodGet, r.Method)
		if "/secrets?s=plain_secret&s=cert_shared&s=secretOne" == r.RequestURI {
			serverResp := server.GeneralResponse{
				Status: "success",
				Data: map[string]interface{}{
					"plain_secret": map[string]interface{}{
						"Type":        "plain",
						"Size":        0,
						"Shared":      false,
						"UserDefined": true,
						"Cert":        nil,
						"ValidFor":    0,
						"Private":     "base64-data",
						"Public":      "base64-data",
					},
					"secretOne": map[string]interface{}{
						"Type":        "symmetric-key",
						"Size":        128,
						"Shared":      true,
						"UserDefined": false,
						"Cert":        nil,
						"ValidFor":    0,
						"Private":     "base64-priv-data",
						"Public":      "base64-priv-data",
					},
					"cert_shared": map[string]interface{}{
						"Type":        "cert-rsa",
						"Size":        2048,
						"Shared":      true,
						"UserDefined": false,
						"Cert":        "base64-cert-data",
						"ValidFor":    14,
						"Private":     "base64-priv-data",
						"Public":      "base64-pub-data",
					},
				},
			}
			assert.NoError(json.NewEncoder(w).Encode(serverResp))
			return
		}
		if "/secrets?s=restricted_secret" == r.RequestURI {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer s.Close()
	options := &secretGetOptions{
		host: host,
		secretIDs: []string{
			"plain_secret",
			"cert_shared",
			"secretOne",
		},
		output: "",
		clCert: tls.Certificate{},
		caCert: []*pem.Block{cert},
	}
	err := cliSecretGet(options)
	assert.NoError(err)

	options.secretIDs = []string{"restricted_secret"}
	err = cliSecretGet(options)
	assert.Error(err)

	options.secretIDs = []string{"this should cause an error"}
	err = cliSecretGet(options)
	assert.Error(err)
}
