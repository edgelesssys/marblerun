/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/edgelesssys/marblerun/cli/internal/file"
	test "github.com/edgelesssys/marblerun/test"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConsolidateManifest(t *testing.T) {
	assert := assert.New(t)
	log := []string{
		`{"time":"1970-01-01T01:00:00.0","update":"initial manifest set"}`,
		`{"time":"1970-01-01T02:00:00.0","update":"SecurityVersion increased","user":"admin","package":"frontend","new version":5}`,
		`{"time":"1970-01-01T03:00:00.0","update":"SecurityVersion increased","user":"admin","package":"frontend","new version":5}`,
		`{"time":"1970-01-01T04:00:00.0","update":"SecurityVersion increased","user":"admin","package":"frontend","new version":8}`,
		`{"time":"1970-01-01T05:00:00.0","update":"SecurityVersion increased","user":"admin","package":"frontend","new version":12}`,
	}

	manifest, err := consolidateManifest([]byte(test.ManifestJSON), log)
	assert.NoError(err)
	assert.Contains(manifest, `"SecurityVersion": 12`)
	assert.NotContains(manifest, `"RecoveryKeys"`)
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
	// 4 should be removed completely since it only contains empty maps
	assert.NotContains(removedMap, `"4"`)
}

func TestCliManifestSet(t *testing.T) {
	testCases := map[string]struct {
		setMnfErr      error
		setMnfResponse map[string][]byte
		file           *file.Handler
		wantErr        bool
	}{
		"success": {
			file: file.New("unit-test", afero.NewMemMapFs()),
		},
		"success with secrets": {
			setMnfResponse: map[string][]byte{"secret": []byte("secret")},
			file:           nil,
		},
		"success with secrets and file": {
			setMnfResponse: map[string][]byte{"secret": []byte("secret")},
			file:           file.New("unit-test", afero.NewMemMapFs()),
		},
		"post error": {
			setMnfErr: assert.AnError,
			wantErr:   true,
		},
		"writing file error": {
			setMnfResponse: map[string][]byte{"secret": []byte("secret")},
			file:           file.New("unit-test", afero.NewReadOnlyFs(afero.NewMemMapFs())),
			wantErr:        true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			cmd := &cobra.Command{}
			var out bytes.Buffer
			cmd.SetOut(&out)

			err := cliManifestSet(cmd, tc.file, func(context.Context) (map[string][]byte, error) {
				return tc.setMnfResponse, tc.setMnfErr
			})

			if tc.wantErr {
				assert.Error(err)
				return
			}

			require.NoError(err)
			assert.Contains(out.String(), "Manifest successfully set")

			if tc.setMnfResponse != nil {
				respJSON, err := json.Marshal(struct {
					RecoverySecrets map[string][]byte
				}{RecoverySecrets: tc.setMnfResponse})
				require.NoError(err)

				if tc.file != nil {
					manifestResponse, err := tc.file.Read()
					require.NoError(err)
					assert.Equal(respJSON, manifestResponse)
				} else {
					assert.Contains(out.String(), string(respJSON))
				}
			}
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

func TestGetSignatureFromString(t *testing.T) {
	require := require.New(t)

	testValue := []byte(`{"TestSignature": "signature"}`)
	hash := sha256.Sum256(testValue)
	directSignature := hash[:]

	testCases := map[string]struct {
		signature string
		expected  []byte
		fs        afero.Afero
		wantErr   bool
	}{
		"direct signature": {
			signature: hex.EncodeToString(directSignature),
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
			expected: func() []byte {
				hash := sha256.Sum256([]byte(`{"TestSignature":"signature"}`)) // JSON converted from YAML has no whitespace
				return hash[:]
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
			assert := assert.New(t)
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

func TestManifestUpdateGet(t *testing.T) {
	testCases := map[string]struct {
		getManifest    func(context.Context) ([]byte, []string, error)
		displayMissing bool
		wantErr        bool
	}{
		"success": {
			getManifest: func(context.Context) ([]byte, []string, error) {
				return []byte(`"manifest"`), []string{"user1", "user2"}, nil
			},
		},
		"success display missing": {
			getManifest: func(context.Context) ([]byte, []string, error) {
				return []byte(`"manifest"`), []string{"user1", "user2"}, nil
			},
			displayMissing: true,
		},
		"get error": {
			getManifest: func(context.Context) ([]byte, []string, error) {
				return nil, nil, assert.AnError
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			var out bytes.Buffer

			err := cliManifestUpdateGet(context.Background(), &out, tc.displayMissing, tc.getManifest)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.NotEmpty(out.String())
		})
	}
}
