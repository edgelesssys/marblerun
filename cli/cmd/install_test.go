package cmd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"reflect"
	"testing"

	"github.com/edgelesssys/marblerun/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	kubeErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
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

func TestInstallWebhook(t *testing.T) {
	assert := assert.New(t)

	testClient := fake.NewSimpleClientset()
	testClient.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{
		Major: "1",
		Minor: "18",
	}

	testValues, err := installWebhook(testClient)
	assert.NoError(err)
	assert.Equal("marbleInjector.start=true", testValues[0], "failed to set start to true")
	assert.Contains(testValues[1], "LS0t", "failed to set CABundle")
}

func TestGetSGXResourceKey(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	testClient := fake.NewSimpleClientset()

	// Test Intel Device Plugin
	intelSGXNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "intel-sgx-node",
		},
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				util.IntelEnclave:   resource.MustParse("10"),
				util.IntelEpc:       resource.MustParse("500"),
				util.IntelProvision: resource.MustParse("10"),
			},
		},
	}
	_, err := testClient.CoreV1().Nodes().Create(context.TODO(), intelSGXNode, metav1.CreateOptions{})
	require.NoError(err)

	resourceKey, err := getSGXResourceKey(testClient)
	assert.NoError(err)
	assert.Equal(util.IntelEpc.String(), resourceKey)
}

func TestErrorAndCleanup(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	testClient := fake.NewSimpleClientset()
	testClient.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{
		Major: "1",
		Minor: "19",
	}

	testError := errors.New("test")
	err := errorAndCleanup(testError, testClient)
	assert.Equal(testError, err)

	// Create and test for CSR
	csr := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: webhookName,
		},
		Spec: certv1.CertificateSigningRequestSpec{
			Request:    []byte{0xAA, 0xAA, 0xAA},
			SignerName: "kubernetes.io/kubelet-serving",
			Usages: []certv1.KeyUsage{
				"key encipherment", "digital signature", "server auth",
			},
		},
	}

	_, err = testClient.CertificatesV1().CertificateSigningRequests().Create(context.TODO(), csr, metav1.CreateOptions{})
	require.NoError(err)

	_, err = testClient.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), webhookName, metav1.GetOptions{})
	require.NoError(err)

	err = errorAndCleanup(testError, testClient)
	assert.Equal(testError, err)

	_, err = testClient.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), webhookName, metav1.GetOptions{})
	assert.True(kubeErrors.IsNotFound(err))
}
