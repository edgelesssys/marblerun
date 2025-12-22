/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"reflect"
	"testing"

	"github.com/edgelesssys/marblerun/cli/internal/helm"
	"github.com/edgelesssys/marblerun/util/k8sutil"
	"github.com/spf13/cobra"
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
	testClient := fake.NewClientset()
	ctx := context.Background()

	testKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(err)
	crt := []byte{0xAA, 0xAA, 0xAA}

	newNamespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: helm.Namespace,
		},
	}
	_, err = testClient.CoreV1().Namespaces().Create(ctx, newNamespace1, metav1.CreateOptions{})
	require.NoError(err)

	err = createSecret(ctx, helm.Namespace, testKey, crt, testClient)
	require.NoError(err)
	_, err = testClient.CoreV1().Secrets(helm.Namespace).Get(context.TODO(), "marble-injector-webhook-certs", metav1.GetOptions{})
	require.NoError(err)

	// we should get an error since the secret was already created in the previous step
	err = createSecret(ctx, helm.Namespace, testKey, crt, testClient)
	require.Error(err)
}

func TestGetCertificateHandler(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	testClient := fake.NewClientset()

	var out bytes.Buffer

	testClient.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{
		Major:      "1",
		Minor:      "19",
		GitVersion: "v1.19.4",
	}
	testHandler, err := getCertificateHandler(&out, testClient, helm.Namespace)
	require.NoError(err)
	assert.Equal("*cmd.certificateV1", reflect.TypeOf(testHandler).String())
	assert.Empty(out.String())
	out.Reset()

	testClient.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{
		Major:      "1",
		Minor:      "18",
		GitVersion: "v1.18.4",
	}
	testHandler, err = getCertificateHandler(&out, testClient, helm.Namespace)
	require.NoError(err)
	assert.Equal("*cmd.certificateLegacy", reflect.TypeOf(testHandler).String())
	assert.NotEmpty(out.String())
	out.Reset()

	testClient.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{
		Major:      "1",
		Minor:      "24+",
		GitVersion: "v1.24.3-2+63243a96d1c393",
	}
	testHandler, err = getCertificateHandler(&out, testClient, helm.Namespace)
	require.NoError(err)
	assert.Equal("*cmd.certificateV1", reflect.TypeOf(testHandler).String())
	assert.Empty(out.String())
}

func TestVerifyNamespace(t *testing.T) {
	require := require.New(t)
	testClient := fake.NewClientset()
	ctx := context.Background()

	_, err := testClient.CoreV1().Namespaces().Get(ctx, "test-space", metav1.GetOptions{})
	require.Error(err)

	// namespace does not exist, it should be created here
	err = verifyNamespace(ctx, "test-space", testClient)
	require.NoError(err)

	_, err = testClient.CoreV1().Namespaces().Get(context.TODO(), "test-space", metav1.GetOptions{})
	require.NoError(err)

	// namespace exists, should return nil
	err = verifyNamespace(ctx, "test-space", testClient)
	require.NoError(err)
}

func TestInstallWebhook(t *testing.T) {
	testCases := map[string]struct {
		kubeClient *fake.Clientset
		cmChecker  stubCMChecker
		assert     func(t *testing.T, values []string, err error)
	}{
		"set up webhook certs": {
			kubeClient: func() *fake.Clientset {
				testClient := fake.NewClientset()
				testClient.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{
					Major:      "1",
					Minor:      "18",
					GitVersion: "v1.18.4",
				}
				return testClient
			}(),
			cmChecker: stubCMChecker{err: assert.AnError},
			assert: func(t *testing.T, values []string, err error) {
				assert.NoError(t, err)
				require.Len(t, values, 2)
				assert.Equal(t, "marbleInjector.start=true", values[0], "failed to set start to true")
				assert.Contains(t, values[1], "LS0t", "failed to set CABundle")
			},
		},
		"use cert-manager": {
			kubeClient: fake.NewClientset(),
			cmChecker:  stubCMChecker{err: nil},
			assert: func(t *testing.T, values []string, err error) {
				assert.NoError(t, err)
				require.Len(t, values, 2)
				assert.Equal(t, "marbleInjector.start=true", values[0], "failed to set start to true")
				assert.Equal(t, "marbleInjector.useCertManager=true", values[1], "failed to set useCertManager to true")
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			cmd := &cobra.Command{}
			var out bytes.Buffer
			cmd.SetOut(&out)

			testValues, err := installWebhookCerts(cmd, tc.kubeClient, tc.cmChecker, helm.Namespace)
			tc.assert(t, testValues, err)
		})
	}
}

func TestGetSGXResourceKey(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	testClient := fake.NewClientset()
	ctx := context.Background()

	// Test Intel Device Plugin
	intelSGXNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "intel-sgx-node",
		},
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				k8sutil.IntelEnclave:   resource.MustParse("10"),
				k8sutil.IntelEpc:       resource.MustParse("500"),
				k8sutil.IntelProvision: resource.MustParse("10"),
			},
		},
	}
	_, err := testClient.CoreV1().Nodes().Create(ctx, intelSGXNode, metav1.CreateOptions{})
	require.NoError(err)

	resourceKey, err := getSGXResourceKey(ctx, testClient)
	assert.NoError(err)
	assert.Equal(k8sutil.IntelEpc.String(), resourceKey)
}

func TestErrorAndCleanup(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	testClient := fake.NewClientset()
	testClient.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{
		Major:      "1",
		Minor:      "19",
		GitVersion: "v1.19.4",
	}
	ctx := context.Background()

	testError := errors.New("test")
	err := errorAndCleanup(ctx, testError, testClient, helm.Namespace)
	assert.Equal(testError, err)

	// Create and test for CSR
	csr := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: webhookDNSName(helm.Namespace),
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

	_, err = testClient.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), webhookDNSName(helm.Namespace), metav1.GetOptions{})
	require.NoError(err)

	err = errorAndCleanup(ctx, testError, testClient, helm.Namespace)
	assert.Equal(testError, err)

	_, err = testClient.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), webhookDNSName(helm.Namespace), metav1.GetOptions{})
	assert.True(kubeErrors.IsNotFound(err))
}

type stubCMChecker struct {
	err error
}

func (s stubCMChecker) Check(_ context.Context) error {
	return s.err
}
