// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/server"
	"github.com/edgelesssys/marblerun/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
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

func TestConsolidateManifest(t *testing.T) {
	assert := assert.New(t)
	log := []byte(`{"time":"1970-01-01T01:00:00.0","update":"initial manifest set"}
{"time":"1970-01-01T02:00:00.0","update":"SecurityVersion increased","user":"admin","package":"frontend","new version":5}
{"time":"1970-01-01T03:00:00.0","update":"SecurityVersion increased","user":"admin","package":"frontend","new version":5}
{"time":"1970-01-01T04:00:00.0","update":"SecurityVersion increased","user":"admin","package":"frontend","new version":8}
{"time":"1970-01-01T05:00:00.0","update":"SecurityVersion increased","user":"admin","package":"frontend","new version":12}`)

	manifest, err := consolidateManifest([]byte(test.ManifestJSON), log)
	assert.NoError(err)
	assert.Contains(manifest, `"SecurityVersion": 12`)
	assert.NotContains(manifest, `"RecoveryKeys"`)
}

func TestDecodeManifest(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	type responseStruct struct {
		Manifest []byte
	}

	wrapped, err := json.Marshal(responseStruct{[]byte(test.ManifestJSON)})
	require.NoError(err)

	manifest, err := decodeManifest(false, gjson.GetBytes(wrapped, "Manifest").String(), "", nil)
	assert.NoError(err)
	assert.Equal(test.ManifestJSON, manifest)
}

func TestRemoveNil(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	testMap := map[string]interface{}{
		"1": "TestValue",
		"2": map[string]interface{}{
			"2.1": "TestValue",
			"2.2": nil,
		},
		"3": nil,
		"4": map[string]interface{}{
			"4.1": map[string]interface{}{
				"4.1.1": nil,
				"4.1.2": map[string]interface{}{},
			},
		},
	}

	rawMap, err := json.Marshal(testMap)
	require.NoError(err)

	removeNil(testMap)

	removedMap, err := json.Marshal(testMap)
	require.NoError(err)
	assert.NotEqual(rawMap, removedMap)
	// three should be removed since its nil
	assert.NotContains(removedMap, `"3"`)
	// 2.2 should be removed since its nil, but 2 stays since 2.1 is not nil
	assert.NotContains(removedMap, `"2.2"`)
	// 4 should be removed completly since it only contains empty maps
	assert.NotContains(removedMap, `"4"`)
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

	var out bytes.Buffer

	err = cliManifestSet(&out, []byte("00"), host, []*pem.Block{cert}, "")
	require.NoError(err)

	err = cliManifestSet(&out, []byte("11"), host, []*pem.Block{cert}, "")
	require.NoError(err)

	responseFile := filepath.Join(dir, "tmp-recovery.json")
	err = cliManifestSet(&out, []byte("11"), host, []*pem.Block{cert}, responseFile)
	require.NoError(err)

	err = cliManifestSet(&out, []byte("22"), host, []*pem.Block{cert}, "")
	require.Error(err)

	err = cliManifestSet(&out, []byte("55"), host, []*pem.Block{cert}, "")
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

	client, err := restClient([]*pem.Block{cert}, nil)
	require.NoError(err)

	var out bytes.Buffer

	err = cliManifestUpdate(&out, []byte("00"), host, client)
	require.NoError(err)

	err = cliManifestUpdate(&out, []byte("11"), host, client)
	require.Error(err)

	err = cliManifestUpdate(&out, []byte("22"), host, client)
	require.Error(err)

	err = cliManifestUpdate(&out, []byte("33"), host, client)
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

	var out bytes.Buffer

	err := cliManifestVerify(&out, "TestSignature", host, []*pem.Block{cert})
	assert.NoError(err)
	assert.Equal("OK\n", out.String())

	err = cliManifestVerify(&out, "InvalidSignature", host, []*pem.Block{cert})
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

func TestManifestUpdateAcknowledge(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/update-manifest", r.RequestURI)
		assert.Equal(http.MethodPost, r.Method)

		serverResp := server.GeneralResponse{
			Status: "success",
			Data:   "acknowledgement successful",
		}

		assert.NoError(json.NewEncoder(w).Encode(serverResp))
	}))
	defer s.Close()

	client, err := restClient([]*pem.Block{cert}, nil)
	require.NoError(err)

	var out bytes.Buffer

	err = cliManifestUpdateAcknowledge(&out, []byte("manifest"), host, client)
	assert.NoError(err)
}

func TestManifestUpdateGet(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	manifest := []byte(`{"foo": "bar"}`)

	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/update-manifest", r.RequestURI)
		assert.Equal(http.MethodGet, r.Method)

		serverResp := server.GeneralResponse{
			Status: "success",
			Data: struct {
				Manifest     []byte   `json:"manifest"`
				Message      string   `json:"message"`
				MissingUsers []string `json:"missingUsers"`
			}{
				Manifest:     manifest,
				Message:      "message",
				MissingUsers: []string{"user1", "user2"},
			},
		}

		assert.NoError(json.NewEncoder(w).Encode(serverResp))
	}))
	defer s.Close()

	client, err := restClient([]*pem.Block{cert}, nil)
	require.NoError(err)

	var out bytes.Buffer

	err = cliManifestUpdateGet(&out, host, client, false)
	assert.NoError(err)
	assert.Equal(manifest, out.Bytes())

	out.Reset()
	err = cliManifestUpdateGet(&out, host, client, true)
	assert.NoError(err)
	assert.True(strings.Contains(out.String(), "message"))
	assert.True(strings.Contains(out.String(), "user1"))
	assert.True(strings.Contains(out.String(), "user2"))
}

func TestManifestUpdateCancel(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/update-cancel", r.RequestURI)
		assert.Equal(http.MethodPost, r.Method)

		serverResp := server.GeneralResponse{
			Status: "success",
			Data:   "cancel successful",
		}

		assert.NoError(json.NewEncoder(w).Encode(serverResp))
	}))
	defer s.Close()

	client, err := restClient([]*pem.Block{cert}, nil)
	require.NoError(err)

	var out bytes.Buffer

	err = cliManifestUpdateCancel(&out, host, client)
	assert.NoError(err)
}
