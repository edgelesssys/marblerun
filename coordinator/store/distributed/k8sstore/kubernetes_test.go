//go:build integration

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package k8sstore

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Run with KUBEBUILDER_ASSETS set and Helm on PATH. Never uses an existing cluster.
func TestKubernetesState(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS to run the disposable API-server integration test")
	}
	useExisting := false
	env := &envtest.Environment{UseExistingCluster: &useExisting}
	env.ControlPlane.GetAPIServer().Configure().Set("advertise-address", "127.0.0.1")
	cfg, err := env.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, env.Stop()) })
	admin, err := kubernetes.NewForConfig(cfg)
	require.NoError(t, err)
	ctx := t.Context()
	namespace := "state-test"
	_, err = admin.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}, metav1.CreateOptions{})
	require.NoError(t, err)
	// Exercise the actual chart's access grant, not a hand-maintained test Role.
	rendered, err := exec.CommandContext(ctx, "helm", "template", "marblerun", "../../../../charts", "--namespace", namespace,
		"--set", "coordinator.distributedDeployment=true", "--set", "coordinator.chunkedState=true").Output()
	require.NoError(t, err)
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(rendered), 4096)
	for {
		var raw runtime.RawExtension
		err := decoder.Decode(&raw)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if len(raw.Raw) == 0 {
			continue
		}
		obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(raw.Raw, nil, nil)
		require.NoError(t, err)
		switch obj := obj.(type) {
		case *corev1.ServiceAccount:
			_, err = admin.CoreV1().ServiceAccounts(namespace).Create(ctx, obj, metav1.CreateOptions{})
		case *rbacv1.Role:
			_, err = admin.RbacV1().Roles(namespace).Create(ctx, obj, metav1.CreateOptions{})
		case *rbacv1.RoleBinding:
			_, err = admin.RbacV1().RoleBindings(namespace).Create(ctx, obj, metav1.CreateOptions{})
		}
		require.NoError(t, err)
	}
	userConfig := rest.CopyConfig(cfg)
	userConfig.Impersonate.UserName = "system:serviceaccount:" + namespace + ":marblerun-coordinator"
	userConfig.QPS, userConfig.Burst = 100, 200
	api, err := kubernetes.NewForConfig(userConfig)
	require.NoError(t, err)
	c := New(api, namespace, "marblerun-state", false, prometheus.NewRegistry(), zaptest.NewLogger(t))
	// RBAC authorizer caches may take a moment to observe the new binding.
	require.Eventually(t, func() bool { _, err := c.GetState(ctx); return err == nil }, 10*time.Second, 100*time.Millisecond)
	state := loadTestState(t, c)
	state.SealedKey = bytes.Repeat([]byte{0x91}, 123)
	state.SealedData = bytes.Repeat([]byte{0x4b}, corev1.MaxSecretSize-123)
	require.NoError(t, c.SaveState(ctx, state))
	state = loadTestState(t, c)
	oversized := state.StateRef.(*corev1.Secret).DeepCopy()
	oversized.Data["extra"] = []byte{1}
	_, err = api.CoreV1().Secrets(namespace).Update(ctx, oversized, metav1.UpdateOptions{})
	require.True(t, k8serrors.IsInvalid(err), "API must reject a Secret one byte over the limit: %v", err)
	state.SealedData = append(state.SealedData, 0x17)
	require.ErrorContains(t, c.SaveState(ctx, state), "enable coordinator.chunkedState")
	c.chunking = true
	require.NoError(t, c.SaveState(ctx, state))
	got := loadTestState(t, c)
	require.Equal(t, state.SealedData, got.SealedData)
	require.Equal(t, state.SealedKey, got.SealedKey)

	// Two independent replicas publish the same next revision with different data.
	other := New(api, namespace, "marblerun-state", false, nil, zaptest.NewLogger(t))
	a, b := loadTestState(t, c), loadTestState(t, other)
	a.SealedData, b.SealedData = []byte("winner A"), []byte("winner B")
	var wg sync.WaitGroup
	var results [2]error
	wg.Go(func() { results[0] = c.SaveState(ctx, a) })
	wg.Go(func() { results[1] = other.SaveState(ctx, b) })
	wg.Wait()
	require.NotEqual(t, results[0] == nil, results[1] == nil)
	got = loadTestState(t, c)
	if results[0] == nil {
		require.Equal(t, a.SealedData, got.SealedData)
	} else {
		require.Equal(t, b.SealedData, got.SealedData)
	}

	// Test the configured capacity on the real API.
	for _, size := range []int{4 * 1024 * 1024, maxStateSize} {
		state = loadTestState(t, c)
		state.SealedData = bytes.Repeat([]byte{byte(size >> 20)}, size)
		start := time.Now()
		require.NoError(t, c.SaveState(ctx, state))
		got = loadTestState(t, c)
		require.Equal(t, state.SealedData, got.SealedData)
		t.Logf("%d MiB save and reload: %s", size>>20, time.Since(start))
	}
	state = loadTestState(t, c)
	state.SealedData = bytes.Repeat([]byte{0x31}, chunkSize+17) // Fits inline, but stays chunked.
	require.NoError(t, c.SaveState(ctx, state))
	got = loadTestState(t, c)
	head := got.StateRef.(*corev1.Secret)
	before := head.Annotations[revisionAnnotation]
	page, err := c.client.listSecrets(ctx, namespace, metav1.ListOptions{LabelSelector: headLabel, Limit: 1})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	require.Empty(t, page.Items[0].Data, "GC listings must not download ciphertext")
	require.NotEmpty(t, page.Continue)
	next, err := c.client.listSecrets(ctx, namespace, metav1.ListOptions{LabelSelector: headLabel, Limit: 1, Continue: page.Continue})
	require.NoError(t, err)
	require.NotEqual(t, page.Items[0].Name, next.Items[0].Name)
	require.NoError(t, c.collect(ctx, head, time.Now().Add(time.Hour)))
	chunks, err := api.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{LabelSelector: headLabel})
	require.NoError(t, err)
	require.Len(t, chunks.Items, 2)
	got = loadTestState(t, c)
	require.Equal(t, state.SealedData, got.SealedData)
	require.Equal(t, before, got.StateRef.(*corev1.Secret).Annotations[revisionAnnotation])
	chunk := chunks.Items[0].DeepCopy()
	chunk.Data["chunk"] = []byte("changed")
	_, err = api.CoreV1().Secrets(namespace).Update(ctx, chunk, metav1.UpdateOptions{})
	require.True(t, k8serrors.IsInvalid(err), "chunk must be immutable: %v", err)
	wrongUID := types.UID("wrong-uid")
	err = api.CoreV1().Secrets(namespace).Delete(ctx, chunk.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &wrongUID}})
	require.True(t, k8serrors.IsConflict(err), "delete must enforce UID: %v", err)
	// Object-level restore changes head UID, chunk names, namespace and ownership,
	// but preserves the sealed bytes, wrapped key, revision and upload identity.
	restoredNamespace := "restored-state"
	_, err = admin.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: restoredNamespace}}, metav1.CreateOptions{})
	require.NoError(t, err)
	restored := head.DeepCopy()
	restored.ObjectMeta = metav1.ObjectMeta{Name: head.Name, Namespace: restoredNamespace, Annotations: head.Annotations}
	restored, err = admin.CoreV1().Secrets(restoredNamespace).Create(ctx, restored, metav1.CreateOptions{})
	require.NoError(t, err)
	var d descriptor
	require.NoError(t, json.Unmarshal(restored.Data[descriptorKey], &d))
	for _, original := range chunks.Items {
		i, err := strconv.Atoi(original.Labels[indexLabel])
		require.NoError(t, err)
		chunk := original.DeepCopy()
		chunk.ObjectMeta = metav1.ObjectMeta{
			Name: chunkName(restored, &d, i), Namespace: restoredNamespace, Labels: original.Labels,
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Secret", Name: restored.Name, UID: restored.UID}},
		}
		chunk.Labels[headLabel] = string(restored.UID)
		_, err = admin.CoreV1().Secrets(restoredNamespace).Create(ctx, chunk, metav1.CreateOptions{})
		require.NoError(t, err)
	}
	restoredClient := New(admin, restoredNamespace, head.Name, false, nil, zaptest.NewLogger(t))
	loaded := loadTestState(t, restoredClient)
	require.Equal(t, got.SealedData, loaded.SealedData)
	require.Equal(t, got.SealedKey, loaded.SealedKey)
	require.Equal(t, "6", loaded.StateRef.(*corev1.Secret).Annotations[revisionAnnotation])
	require.NoError(t, restoredClient.SaveState(ctx, loaded))
	require.Equal(t, "7", loadTestState(t, restoredClient).StateRef.(*corev1.Secret).Annotations[revisionAnnotation])
}
