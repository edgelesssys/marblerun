// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/edgelesssys/marblerun/test"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testLog = []byte(`{"time":"1970-01-01T01:00:00.0","update":"initial manifest set"}
{"time":"1970-01-01T02:00:00.0","update":"SecurityVersion increased","user":"admin","package":"frontend","new version":5}
{"time":"1970-01-01T03:00:00.0","update":"SecurityVersion increased","user":"admin","package":"frontend","new version":5}
{"time":"1970-01-01T04:00:00.0","update":"SecurityVersion increased","user":"admin","package":"frontend","new version":8}
{"time":"1970-01-01T05:00:00.0","update":"SecurityVersion increased","user":"admin","package":"frontend","new version":12}`)

func TestConsolidateManifest(t *testing.T) {
	assert := assert.New(t)
	log := testLog

	manifest, err := consolidateManifest([]byte(test.ManifestJSON), log)
	assert.NoError(err)
	assert.Contains(manifest, `"SecurityVersion": 12`)
	assert.NotContains(manifest, `"RecoveryKeys"`)
}

func TestDecodeManifest(t *testing.T) {
	assert := assert.New(t)

	manifestRaw := base64.StdEncoding.EncodeToString([]byte(test.ManifestJSON))

	manifest, err := decodeManifest(context.Background(), false, manifestRaw, &stubGetter{})
	assert.NoError(err)
	assert.Equal(test.ManifestJSON, manifest)

	getter := &stubGetter{response: testLog}
	manifest, err = decodeManifest(context.Background(), true, string(manifestRaw), getter)
	assert.NoError(err)
	assert.Contains(manifest, `"SecurityVersion": 12`)
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
	someErr := errors.New("failed")
	testCases := map[string]struct {
		poster  *stubPoster
		file    *file.Handler
		wantErr bool
	}{
		"success": {
			poster: &stubPoster{},
			file:   file.New("unit-test", afero.NewMemMapFs()),
		},
		"success with secrets": {
			poster: &stubPoster{response: []byte("secret")},
			file:   nil,
		},
		"success with secrets and file": {
			poster: &stubPoster{response: []byte("secret")},
			file:   file.New("unit-test", afero.NewMemMapFs()),
		},
		"post error": {
			poster:  &stubPoster{err: someErr},
			wantErr: true,
		},
		"writing file error": {
			poster:  &stubPoster{response: []byte("secret")},
			file:    file.New("unit-test", afero.NewReadOnlyFs(afero.NewMemMapFs())),
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			cmd := &cobra.Command{}
			var out bytes.Buffer
			cmd.SetOut(&out)

			err := cliManifestSet(cmd, []byte("manifest"), tc.file, tc.poster)

			if tc.wantErr {
				assert.Error(err)
				return
			}

			require.NoError(err)
			assert.Contains(out.String(), "Manifest successfully set")
			assert.Equal(rest.ManifestEndpoint, tc.poster.requestPath)
			assert.Equal(rest.ContentJSON, tc.poster.header)

			if tc.poster.response != nil {
				if tc.file != nil {
					manifestResponse, err := tc.file.Read()
					require.NoError(err)
					assert.Equal(tc.poster.response, manifestResponse)
				} else {
					assert.Contains(out.String(), string(tc.poster.response))
				}
			}
		})
	}
}

func TestCliManifestUpdateApply(t *testing.T) {
	testCases := map[string]struct {
		poster  *stubPoster
		wantErr bool
	}{
		"success": {
			poster:  &stubPoster{},
			wantErr: false,
		},
		"error": {
			poster: &stubPoster{
				err: errors.New("failed"),
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			cmd := &cobra.Command{}

			var out bytes.Buffer
			cmd.SetOut(&out)

			err := cliManifestUpdateApply(cmd, []byte("manifest"), tc.poster)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Contains(out.String(), "Update manifest set successfully")
			assert.Equal(rest.UpdateEndpoint, tc.poster.requestPath)
			assert.Equal(rest.ContentJSON, tc.poster.header)
		})
	}
}

func TestLoadManifestFile(t *testing.T) {
	require := require.New(t)

	testCases := map[string]struct {
		file    *file.Handler
		wantErr bool
	}{
		"json data": {
			file: func() *file.Handler {
				file := file.New("unit-test", afero.NewMemMapFs())
				require.NoError(file.Write([]byte(`{"Packages": {"APackage": {"SignerID": "1234","ProductID": 0,"SecurityVersion": 0,"Debug": false}}}`)))
				return file
			}(),
		},
		"yaml data": {
			file: func() *file.Handler {
				file := file.New("unit-test", afero.NewMemMapFs())
				require.NoError(file.Write([]byte(`
Package:
  SomePackage:
    Debug: false
    ProductID: 0
    SecurityVersion: 0
    SignerID: "1234"
`)))
				return file
			}(),
		},
		"invalid data": {
			file: func() *file.Handler {
				file := file.New("unit-test", afero.NewMemMapFs())
				require.NoError(file.Write([]byte(`
				Invalid YAML:
				This should return an error`)))
				return file
			}(),
			wantErr: true,
		},
		"file not found": {
			file:    file.New("unit-test", afero.NewReadOnlyFs(afero.NewMemMapFs())),
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			dataJSON, err := loadManifestFile(tc.file)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.True(json.Valid(dataJSON))
		})
	}
}

func TestCliManifestSignature(t *testing.T) {
	assert := assert.New(t)

	testValue := []byte("Test")
	hash := sha256.Sum256(testValue)
	signature := hex.EncodeToString(hash[:])
	assert.Equal(signature, cliManifestSignature(testValue))
}

func TestCliManifestVerify(t *testing.T) {
	testCases := map[string]struct {
		localSignature string
		getter         *stubGetter
		wantErr        bool
	}{
		"success": {
			localSignature: "signature",
			getter:         &stubGetter{response: []byte(`{"ManifestSignature": "signature"}`)},
		},
		"get error": {
			localSignature: "signature",
			getter:         &stubGetter{err: errors.New("failed")},
			wantErr:        true,
		},
		"invalid signature": {
			localSignature: "signature",
			getter:         &stubGetter{response: []byte(`{"ManifestSignature": "invalid"}`)},
			wantErr:        true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			cmd := &cobra.Command{}

			var out bytes.Buffer
			cmd.SetOut(&out)

			err := cliManifestVerify(cmd, tc.localSignature, tc.getter)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Equal("OK\n", out.String())
		})
	}
}

func TestGetSignatureFromString(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	testValue := []byte(`{"TestSignature": "signature"}`)
	hash := sha256.Sum256(testValue)
	directSignature := hex.EncodeToString(hash[:])

	testCases := map[string]struct {
		signature string
		expected  string
		fs        afero.Afero
		wantErr   bool
	}{
		"direct signature": {
			signature: directSignature,
			expected:  directSignature,
			fs:        afero.Afero{Fs: afero.NewMemMapFs()},
		},
		"json manifest file": {
			signature: "testSignature",
			expected:  directSignature,
			fs: func() afero.Afero {
				fs := afero.Afero{Fs: afero.NewMemMapFs()}
				require.NoError(fs.WriteFile("testSignature", testValue, 0o644))
				return fs
			}(),
		},
		"yaml manifest file": {
			signature: "testSignature",
			expected: func() string {
				hash := sha256.Sum256([]byte(`{"TestSignature":"signature"}`)) // JSON converted from YAML has no whitespace
				return hex.EncodeToString(hash[:])
			}(),
			fs: func() afero.Afero {
				fs := afero.Afero{Fs: afero.NewMemMapFs()}
				require.NoError(fs.WriteFile("testSignature", []byte(`TestSignature: signature`), 0o644))
				return fs
			}(),
		},
		"invalid file": {
			signature: "testSignature",
			fs: func() afero.Afero {
				fs := afero.Afero{Fs: afero.NewMemMapFs()}
				require.NoError(fs.WriteFile("testSignature", []byte(`invalid: manifest: file`), 0o644))
				return fs
			}(),
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			testSignature, err := getSignatureFromString(tc.signature, tc.fs)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Equal(tc.expected, testSignature)
		})
	}
}

func TestManifestUpdateAcknowledge(t *testing.T) {
	testCases := map[string]struct {
		poster  *stubPoster
		wantErr bool
	}{
		"success": {
			poster:  &stubPoster{response: []byte("response")},
			wantErr: false,
		},
		"error": {
			poster: &stubPoster{
				err: errors.New("failed"),
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			cmd := &cobra.Command{}

			var out bytes.Buffer
			cmd.SetOut(&out)

			err := cliManifestUpdateAcknowledge(cmd, []byte("manifest"), tc.poster)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Contains(out.String(), "Acknowledgement successful")
			assert.Contains(out.String(), string(tc.poster.response))
			assert.Equal(rest.UpdateStatusEndpoint, tc.poster.requestPath)
			assert.Equal(rest.ContentJSON, tc.poster.header)
		})
	}
}

func TestManifestUpdateGet(t *testing.T) {
	testCases := map[string]struct {
		getter         *stubGetter
		displayMissing bool
		wantErr        bool
	}{
		"success": {
			getter: &stubGetter{
				response: []byte(`{"manifest": "bWFuaWZlc3Q=", "missingUsers": ["user1", "user2"]}`),
			},
		},
		"success display missing": {
			getter: &stubGetter{
				response: []byte(`{"manifest": "bWFuaWZlc3Q=", "missingUsers": ["user1", "user2"]}`),
			},
			displayMissing: true,
		},
		"get error": {
			getter:  &stubGetter{err: errors.New("failed")},
			wantErr: true,
		},
		"invalid manifest encoding": {
			getter: &stubGetter{
				response: []byte(`{"manifest": "_invalid_data_", "missingUsers": ["user1", "user2"]}`),
			},
			displayMissing: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			var out bytes.Buffer

			err := cliManifestUpdateGet(context.Background(), &out, tc.displayMissing, tc.getter)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.NotEmpty(out.String())
		})
	}
}

func TestManifestUpdateCancel(t *testing.T) {
	testCases := map[string]struct {
		poster  *stubPoster
		wantErr bool
	}{
		"success": {
			poster:  &stubPoster{},
			wantErr: false,
		},
		"error": {
			poster: &stubPoster{
				err: errors.New("failed"),
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			cmd := &cobra.Command{}

			var out bytes.Buffer
			cmd.SetOut(&out)

			err := cliManifestUpdateCancel(cmd, tc.poster)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Contains(out.String(), "Cancellation successful")
			assert.Equal(rest.UpdateCancelEndpoint, tc.poster.requestPath)
		})
	}
}
