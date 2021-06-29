package cmd

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
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
		type testResp struct {
			ManifestSignature string
		}

		data := testResp{
			ManifestSignature: "TestSignature",
		}

		serverResp := server.GeneralResponse{
			Status: "success",
			Data:   data,
		}

		assert.NoError(json.NewEncoder(w).Encode(serverResp))
	}))
	defer s.Close()

	resp, err := cliDataGet(host, "manifest", "data.ManifestSignature", []*pem.Block{cert})
	require.NoError(err)
	assert.Equal("TestSignature", string(resp))

	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err = cliDataGet(host, "manifest", "data.ManifestSignature", []*pem.Block{cert})
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
	defer s.Close()

	dir, err := ioutil.TempDir("", "unittest")
	require.NoError(err)
	defer os.RemoveAll(dir)

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

func TestLoadJSON(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	tmpFile, err := ioutil.TempFile("", "unittest")
	require.NoError(err)
	defer os.Remove(tmpFile.Name())

	input := []byte(`
{
	"Packages": {
		"APackage": {
			"SignerID": "1234",
			"ProductID": 0,
			"SecurityVersion": 0,
			"Debug": false
		}
	}
}
`)
	assert.True(json.Valid(input))
	_, err = tmpFile.Write(input)
	require.NoError(err)

	dataJSON, err := loadManifestFile(tmpFile.Name())
	require.NoError(err)
	assert.True(json.Valid(dataJSON))
}

func TestLoadYAML(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	tmpFile, err := ioutil.TempFile("", "unittest")
	require.NoError(err)
	defer os.Remove(tmpFile.Name())

	input := []byte(`
Packages:
  APackage:
    Debug: false
    ProductID: 0
    SecurityVersion: 0
    SignerID: "1234"
`)
	assert.False(json.Valid(input))
	_, err = tmpFile.Write(input)
	require.NoError(err)

	dataJSON, err := loadManifestFile(tmpFile.Name())
	require.NoError(err)
	assert.True(json.Valid(dataJSON))
}

func TestLoadFailsOnInvalid(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	tmpFile, err := ioutil.TempFile("", "unittest")
	require.NoError(err)
	defer os.Remove(tmpFile.Name())

	input := []byte(`
Invalid YAML:
This should return an error
`)
	assert.False(json.Valid(input))
	_, err = tmpFile.Write(input)
	require.NoError(err)

	dataJSON, err := loadManifestFile(tmpFile.Name())
	require.Error(err)
	assert.False(json.Valid(dataJSON))

	input = []byte(`
{
	"JSON": "Data",
	"But its invalid",
}
`)

	assert.False(json.Valid(input))
	_, err = tmpFile.Write(input)
	require.NoError(err)

	dataJSON, err = loadManifestFile(tmpFile.Name())
	require.Error(err)
	assert.False(json.Valid(dataJSON))
}

func TestCliManifestSignature(t *testing.T) {
	assert := assert.New(t)

	testValue := []byte("Test")
	hash := sha256.Sum256(testValue)
	signature := hex.EncodeToString(hash[:])
	assert.Equal(signature, cliManifestSignature(testValue))
}

func TestCliManifestVerify(t *testing.T) {
	assert := assert.New(t)

	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/manifest", r.RequestURI)
		assert.Equal(http.MethodGet, r.Method)
		type testResp struct {
			ManifestSignature string
		}

		data := testResp{
			ManifestSignature: "TestSignature",
		}

		serverResp := server.GeneralResponse{
			Status: "success",
			Data:   data,
		}

		assert.NoError(json.NewEncoder(w).Encode(serverResp))
	}))
	defer s.Close()

	err := cliManifestVerify("TestSignature", host, []*pem.Block{cert})
	assert.NoError(err)

	err = cliManifestVerify("InvalidSignature", host, []*pem.Block{cert})
	assert.Error(err)
}

func TestGetSignatureFromString(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	tmpFile, err := ioutil.TempFile("", "unittest")
	require.NoError(err)
	defer os.Remove(tmpFile.Name())

	testValue := []byte("TestSignature")
	hash := sha256.Sum256(testValue)
	directSignature := hex.EncodeToString(hash[:])

	_, err = tmpFile.Write(testValue)
	require.NoError(err)

	testSignature1, err := getSignatureFromString(directSignature)
	assert.NoError(err)
	assert.Equal(directSignature, testSignature1)

	testSignature2, err := getSignatureFromString(tmpFile.Name())
	assert.NoError(err)
	assert.Equal(directSignature, testSignature2)

	_, err = getSignatureFromString("invalidFilename")
	assert.Error(err)
}
