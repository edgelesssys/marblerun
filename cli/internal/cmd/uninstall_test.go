// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"context"
	"testing"

	"github.com/edgelesssys/marblerun/cli/internal/helm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCleanupWebhook(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	testClient := fake.NewSimpleClientset()
	testClient.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{
		Major:      "1",
		Minor:      "19",
		GitVersion: "v1.19.4",
	}
	ctx := context.Background()

	// Try to remove non existent CSR using function
	_, err := testClient.CertificatesV1().CertificateSigningRequests().Get(ctx, webhookName, metav1.GetOptions{})
	require.Error(err)

	err = cleanupCSR(ctx, testClient)
	require.Error(err)
	assert.True(errors.IsNotFound(err), "function returned an error other than not found")

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

	_, err = testClient.CertificatesV1().CertificateSigningRequests().Create(ctx, csr, metav1.CreateOptions{})
	require.NoError(err)

	_, err = testClient.CertificatesV1().CertificateSigningRequests().Get(ctx, webhookName, metav1.GetOptions{})
	require.NoError(err)

	// Remove CSR using function
	err = cleanupCSR(ctx, testClient)
	require.NoError(err)

	_, err = testClient.CertificatesV1().CertificateSigningRequests().Get(ctx, webhookName, metav1.GetOptions{})
	require.Error(err)

	// try changing to version lower than 19 and removing CSR (this should always return nil)
	testClient.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{
		Major:      "1",
		Minor:      "18",
		GitVersion: "v1.18.4",
	}
	err = cleanupCSR(ctx, testClient)
	require.NoError(err)

	// try changing to version string containing non-digit characters and removing the CSR

	_, err = testClient.CertificatesV1().CertificateSigningRequests().Create(ctx, csr, metav1.CreateOptions{})
	require.NoError(err)

	_, err = testClient.CertificatesV1().CertificateSigningRequests().Get(ctx, webhookName, metav1.GetOptions{})
	require.NoError(err)

	testClient.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{
		Major:      "1",
		Minor:      "24+",
		GitVersion: "v1.24.3-2+63243a96d1c393",
	}
	err = cleanupCSR(ctx, testClient)
	require.NoError(err)

	// Try to remove non existent Secret using function
	_, err = testClient.CoreV1().Secrets(helm.Namespace).Get(ctx, "marble-injector-webhook-certs", metav1.GetOptions{})
	require.Error(err)

	err = cleanupSecrets(ctx, testClient)
	require.Error(err)
	assert.True(errors.IsNotFound(err), "function returned an error other than not found")

	// Create Secret and test for Secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "marble-injector-webhook-certs",
			Namespace: helm.Namespace,
		},
		Data: map[string][]byte{
			"tls.crt": {0xAA, 0xAA, 0xAA},
			"tls.key": {0xBB, 0xBB, 0xBB},
		},
	}

	_, err = testClient.CoreV1().Secrets(helm.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	require.NoError(err)

	_, err = testClient.CoreV1().Secrets(helm.Namespace).Get(ctx, "marble-injector-webhook-certs", metav1.GetOptions{})
	require.NoError(err)

	err = cleanupSecrets(ctx, testClient)
	require.NoError(err)
}
