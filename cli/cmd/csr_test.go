package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"
)

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

	testClient := fake.NewSimpleClientset()

	testHandler, err := newCertificateV1(testClient)
	require.NoError(err)

	testKey := testHandler.getKey()
	assert.True(testKey.Equal(testHandler.privKey), "private key of the handler and private key returned by its method were not equal")

	testHandler.timeout = 5
	// this should error with a timeout since the fakeClient does not keep upated resources, but only returns them once on API call
	err = testHandler.signRequest()
	require.Error(err)
	assert.Contains(err.Error(), "certificate signing request was not updated", fmt.Sprintf("failed with unexpected error: %s", err.Error()))

	// we use a different timeout function here, so this should not return an error, but the certificate will be empty
	testCrt, err := testHandler.get()
	require.NoError(err)
	assert.True((len(testCrt) == 0))

	testValues := map[string]interface{}{
		"marbleInjector": map[string]interface{}{
			"start":    false,
			"CABundle": "string",
		},
	}

	testHandler.setCaBundle(testValues)
	assert.Equal(nil, testValues["marbleInjector"].(map[string]interface{})["CABundle"], "failed to remove CABundle")
	assert.Equal(true, testValues["marbleInjector"].(map[string]interface{})["start"], "failed to set start to true")
}

func TestCertificateLegacy(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	testHandler, err := newCertificateLegacy()
	require.NoError(err)
	assert.True(len(testHandler.caCert.Bytes) > 0, "failed creating caCert")

	err = testHandler.signRequest()
	require.NoError(err)
	assert.True(len(testHandler.serverCert.Bytes) > 0, "failed creating serverCert")

	testKey := testHandler.getKey()
	assert.True(testKey.Equal(testHandler.serverPrivKey), "private key of the handler and private key returned by its method were not equal")

	testCrt, err := testHandler.get()
	require.NoError(err)
	assert.True(len(testCrt) > 0, "failed to retrieve server certificate")

	testValues := map[string]interface{}{
		"marbleInjector": map[string]interface{}{
			"start":    false,
			"CABundle": "string",
		},
	}

	testHandler.setCaBundle(testValues)
	assert.Equal(true, testValues["marbleInjector"].(map[string]interface{})["start"], "failed to set start to true")
	assert.NotEqual("string", testValues["marbleInjector"].(map[string]interface{})["CABundle"], "failed to set CABundle")
}
