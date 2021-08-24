// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package manifest

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/edgelesssys/marblerun/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestFile(t *testing.T) {
	dataJSON := []byte(`
{
	"string": "helloworld",
	"stringStruct": {
		"Encoding": "string",
		"NoTemplates": false,
		"Data": "foo"
	},
	"base64": {
		"Encoding": "base64",
		"NoTemplates": true,
		"Data": "YmFy"
	},
	"base64Value": {
		"Encoding": "string",
		"Data": "YmFy"
	},
	"hex": {
		"Encoding": "hex",
		"Data": "4d6172626c6552756e"
	},
	"withoutTemplates": {
		"Encoding": "string",
		"NoTemplates": true,
		"Data": "{{ string .Secrets.symmetricKeyShared }}"
	}
}`)
	assert := assert.New(t)
	require := require.New(t)

	testFiles := make(map[string]File)
	err := json.Unmarshal(dataJSON, &testFiles)
	require.NoError(err)
	assert.Equal("helloworld", testFiles["string"].Data)
	assert.Equal("string", testFiles["string"].Encoding)
	assert.Equal("foo", testFiles["stringStruct"].Data)
	assert.Equal("bar", testFiles["base64"].Data)
	assert.Equal("YmFy", testFiles["base64Value"].Data)
	assert.Equal("MarbleRun", testFiles["hex"].Data)
	assert.Equal("{{ string .Secrets.symmetricKeyShared }}", testFiles["withoutTemplates"].Data)

	_, err = json.Marshal(testFiles)
	assert.NoError(err)
}

func TestManifestCheck(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	var manifest Manifest
	err := json.Unmarshal([]byte(test.ManifestJSON), &manifest)
	require.NoError(err)

	zap, err := zap.NewDevelopment()
	require.NoError(err)
	err = manifest.Check(context.TODO(), zap)
	assert.NoError(err)
}

func TestCertificate(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	block, _ := pem.Decode(test.AdminCert)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(err)

	certJSON, err := json.Marshal(Certificate(*cert))
	assert.NoError(err)

	var cert2 Certificate
	err = json.Unmarshal(certJSON, &cert2)
	assert.NoError(err)
	assert.Equal(cert.Raw, cert2.Raw)
}
