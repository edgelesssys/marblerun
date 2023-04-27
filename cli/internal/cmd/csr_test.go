// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/clientcmd"
)

var MockConfig = `
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: CABundle
    server: https://example.com:443
  name: mock-config
contexts:
- context:
    cluster: mock-config
    user: clusterUser_unit-test_mock-config
`

func TestCreateCSR(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	testKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(err)

	pem, err := createCSR(testKey)
	require.NoError(err)
	assert.Equal("CERTIFICATE REQUEST", pem.Type)
}

func TestCertificateV1(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	ctx := context.Background()

	testClient := fake.NewSimpleClientset()

	testHandler, err := newCertificateV1(testClient)
	require.NoError(err)

	testKey := testHandler.getKey()
	assert.Equal(testKey, testHandler.privKey, "private key of the handler and private key returned by its method were not equal")

	testHandler.timeout = 2
	// this should error with a timeout since the fakeClient does not keep updated resources, but only returns them once on API call
	err = testHandler.signRequest(ctx)
	require.Error(err)
	assert.Contains(err.Error(), "certificate signing request was not updated", fmt.Sprintf("failed with unexpected error: %s", err.Error()))

	// we use a different timeout function here, so this should not return an error, but the certificate will be empty
	testCrt, err := testHandler.get(ctx)
	require.NoError(err)
	assert.True((len(testCrt) == 0))

	configFile, err := os.CreateTemp(os.TempDir(), "unittest")
	require.NoError(err)
	defer os.Remove(configFile.Name())
	err = os.Setenv(clientcmd.RecommendedConfigPathEnvVar, configFile.Name())
	require.NoError(err)
	_, err = configFile.Write([]byte(MockConfig))
	require.NoError(err)

	testValues, err := testHandler.setCaBundle()
	assert.NoError(err)
	assert.Equal("marbleInjector.start=true", testValues[0], "failed to set start to true")
	assert.Equal("marbleInjector.CABundle=CABundle", testValues[1], "failed to set CABundle")
}

func TestCertificateLegacy(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	ctx := context.Background()

	testHandler, err := newCertificateLegacy()
	require.NoError(err)
	assert.True(len(testHandler.caCert.Bytes) > 0, "failed creating caCert")

	err = testHandler.signRequest(ctx)
	require.NoError(err)
	assert.True(len(testHandler.serverCert.Bytes) > 0, "failed creating serverCert")

	testKey := testHandler.getKey()
	assert.Equal(testKey, testHandler.serverPrivKey, "private key of the handler and private key returned by its method were not equal")

	testCrt, err := testHandler.get(ctx)
	require.NoError(err)
	assert.True(len(testCrt) > 0, "failed to retrieve server certificate")

	testValues, err := testHandler.setCaBundle()
	assert.NoError(err)
	assert.Equal("marbleInjector.start=true", testValues[0], "failed to set start to true")
	assert.Contains(testValues[1], "LS0t", "failed to set CABundle")
}
