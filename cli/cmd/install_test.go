package cmd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCreateSecret(t *testing.T) {
	require := require.New(t)
	testClient := fake.NewSimpleClientset()

	testKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(err)
	crt := []byte{0xAA, 0xAA, 0xAA}

	newNamespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "marblerun",
		},
	}
	_, err = testClient.CoreV1().Namespaces().Create(context.TODO(), newNamespace1, metav1.CreateOptions{})
	require.NoError(err)

	err = createSecret(testKey, crt, testClient)
	require.NoError(err)
	_, err = testClient.CoreV1().Secrets("marblerun").Get(context.TODO(), "marble-injector-webhook-certs", metav1.GetOptions{})
	require.NoError(err)

	// we should get an error since the secret was already created in the previous step
	err = createSecret(testKey, crt, testClient)
	require.Error(err)
}

func TestGetCertificateHandler(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	testClient := fake.NewSimpleClientset()

	testClient.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{
		Major: "1",
		Minor: "19",
	}
	testHandler, err := getCertificateHandler(testClient)
	require.NoError(err)
	assert.Equal(reflect.TypeOf(testHandler).String(), "*cmd.certificateV1")

	testClient.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{
		Major: "1",
		Minor: "18",
	}
	testHandler, err = getCertificateHandler(testClient)
	require.NoError(err)
	assert.Equal(reflect.TypeOf(testHandler).String(), "*cmd.certificateLegacy")
}

func TestVerifyNamespace(t *testing.T) {
	require := require.New(t)
	testClient := fake.NewSimpleClientset()

	_, err := testClient.CoreV1().Namespaces().Get(context.TODO(), "test-space", metav1.GetOptions{})
	require.Error(err)

	// namespace does not exist, it should be created here
	err = verifyNamespace("test-space", testClient)
	require.NoError(err)

	_, err = testClient.CoreV1().Namespaces().Get(context.TODO(), "test-space", metav1.GetOptions{})
	require.NoError(err)

	// namespace exists, should return nil
	err = verifyNamespace("test-space", testClient)
	require.NoError(err)
}
