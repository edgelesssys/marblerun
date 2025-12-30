//go:build e2e

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"fmt"
	"strings"
	"testing"

	marbleconfig "github.com/edgelesssys/marblerun/marble/config"
	"github.com/edgelesssys/marblerun/test/e2e/cmd"
	"github.com/edgelesssys/marblerun/test/e2e/helm"
	"github.com/edgelesssys/marblerun/util/k8sutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestWebhookCertRenewal(t *testing.T) {
	ctx, assert, require, kubectl, _, _ := createBaseObjects(t)

	namespace := "webhook-test"
	uid, cleanUp, err := kubectl.SetUpNamespace(ctx, namespace)
	require.NoError(err)
	t.Cleanup(cleanUp)
	namespace += "-" + uid

	helm, err := helm.New(t, *kubeConfigPath, namespace)
	require.NoError(err)
	t.Logf("Installing chart %q from %q", namespace, *chartPath)
	extraVals := map[string]any{
		"marbleInjector": map[string]any{
			"start":          true,
			"useCertManager": true,
		},
	}
	uninstall, err := helm.InstallChart(ctx, namespace, namespace, *chartPath, *replicas, defaultTimeout, extraVals)
	require.NoError(err)
	t.Cleanup(uninstall)
	getLogsOnFailure(t, kubectl, namespace)

	// We don't care about initializing the MarbleRun Coordinator for this test.
	// since we only want to test the webhook.
	marbleType := "test"
	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: namespace,
			Labels: map[string]string{
				"marblerun/marbletype": marbleType,
			},
		},

		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "test",
					Image: "ubuntu",
				},
			},
		},
	}

	t.Log("Creating test pod")
	require.Eventually(func() bool {
		_, err := kubectl.CreatePod(ctx, testPod)
		return err == nil
	}, eventuallyTimeout, eventuallyInterval, "Waiting for test pod to be created")

	checkPod := func() {
		var createdPod *corev1.Pod
		require.Eventually(func() bool {
			createdPod, err = kubectl.GetPod(ctx, namespace, testPod.GetName())
			return err == nil
		}, eventuallyTimeout, eventuallyInterval, "Waiting for test pod to be created")

		t.Log("Checking created Pod for injected env vars")
		envVars := createdPod.Spec.Containers[0].Env
		assert.Len(envVars, 4) // expect 4 injected env vars: coordinator addr, marble type, uuid file, and DNS names
		for _, envVar := range envVars {
			switch envVar.Name {
			case marbleconfig.CoordinatorAddr:
				assert.Equal("coordinator-mesh-api."+namespace+":2001", envVar.Value)
			case marbleconfig.Type:
				assert.Equal(marbleType, envVar.Value)
			case marbleconfig.DNSNames:
				assert.Equal(strings.ToLower(fmt.Sprintf("%s,%s.%s,%s.%s.svc.cluster.local", marbleType, marbleType, namespace, marbleType, namespace)), envVar.Value)
			case marbleconfig.UUIDFile:
				assert.Equal(fmt.Sprintf("/%s-uid/uuid-file", marbleType), envVar.Value)
			}
		}
		t.Log("Checking created Pod for injected SGX resources")
		limits := createdPod.Spec.Containers[0].Resources.Limits
		assert.True(limits[k8sutil.IntelEpc].Equal(resource.MustParse("10Mi")))
		assert.True(limits[k8sutil.IntelEnclave].Equal(resource.MustParse("1")))
		assert.True(limits[k8sutil.IntelProvision].Equal(resource.MustParse("1")))
	}
	checkPod()

	t.Log("Creation successful, removing...")
	require.NoError(kubectl.DeletePod(ctx, testPod.GetNamespace(), testPod.GetName()))

	t.Log("Renewing webhook certificate")
	cmd, err := cmd.New(t, "cmctl")
	require.NoError(err)
	_, err = cmd.Run(ctx, "renew", "--namespace", namespace, "--all")
	require.NoError(err)

	assert.Eventually(func() bool {
		_, err := kubectl.CreatePod(ctx, testPod)
		return err == nil
	}, eventuallyTimeout, eventuallyInterval, "Waiting for test pod to be created after webhook cert renewal")
	checkPod()
}
