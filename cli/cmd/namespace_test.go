package cmd

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNameSpaceAdd(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	testClient := fake.NewSimpleClientset()

	// Test adding non existant namespace
	err := cliNameSpaceAdd([]string{"test-space-1"}, testClient, true)
	require.Error(err)

	// Test adding multiple non existant namespaces
	err = cliNameSpaceAdd([]string{"test-space-1", "test-space-2", "test-space-3"}, testClient, true)
	require.Error(err)

	// Create namespace to add to mesh
	newNamespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-space-1",
		},
	}
	_, err = testClient.CoreV1().Namespaces().Create(context.TODO(), newNamespace1, metav1.CreateOptions{})
	require.NoError(err)
	err = cliNameSpaceAdd([]string{"test-space-1"}, testClient, true)
	require.NoError(err)

	injectedNamespace, err := testClient.CoreV1().Namespaces().Get(context.TODO(), "test-space-1", metav1.GetOptions{})
	require.NoError(err)
	assert.Equal(injectedNamespace.Labels["marblerun/inject"], "enabled", "failed to inject marblerun label")
	assert.Equal(injectedNamespace.Labels["marblerun/inject-sgx"], "disabled", "injected sgx label when it shouldnt have")

	// Create two more namespaces
	newNamespace2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-space-2",
		},
	}
	newNamespace3 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-space-3",
		},
	}
	_, err = testClient.CoreV1().Namespaces().Create(context.TODO(), newNamespace2, metav1.CreateOptions{})
	require.NoError(err)
	_, err = testClient.CoreV1().Namespaces().Create(context.TODO(), newNamespace3, metav1.CreateOptions{})
	require.NoError(err)
	err = cliNameSpaceAdd([]string{"test-space-2", "test-space-3"}, testClient, false)
	require.NoError(err)

	injectedNamespace, err = testClient.CoreV1().Namespaces().Get(context.TODO(), "test-space-2", metav1.GetOptions{})
	require.NoError(err)
	assert.Equal(injectedNamespace.Labels["marblerun/inject"], "enabled", "failed to inject marblerun label")
	assert.Equal(injectedNamespace.Labels["marblerun/inject-sgx"], "enabled", "failed to inject marblerun inject-sgx label")

	injectedNamespace, err = testClient.CoreV1().Namespaces().Get(context.TODO(), "test-space-3", metav1.GetOptions{})
	require.NoError(err)
	assert.Equal(injectedNamespace.Labels["marblerun/inject"], "enabled", "failed to inject marblerun label")
	assert.Equal(injectedNamespace.Labels["marblerun/inject-sgx"], "enabled", "failed to inject marblerun inject-sgx label")
}

func TestNameSpaceList(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	testClient := fake.NewSimpleClientset()

	// Test listing on empty
	err := cliNameSpaceList(testClient)
	require.NoError(err)

	// Create and add two namespaces
	newNamespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-space-1",
			Labels: map[string]string{
				"marblerun/inject":     "enabled",
				"marblerun/inject-sgx": "enabled",
			},
		},
	}
	newNamespace2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-space-2",
			Labels: map[string]string{
				"marblerun/inject":     "enabled",
				"marblerun/inject-sgx": "disabled",
			},
		},
	}
	_, err = testClient.CoreV1().Namespaces().Create(context.TODO(), newNamespace1, metav1.CreateOptions{})
	require.NoError(err)
	_, err = testClient.CoreV1().Namespaces().Create(context.TODO(), newNamespace2, metav1.CreateOptions{})
	require.NoError(err)

	list, err := selectNamespaces(testClient)
	require.NoError(err)
	assert.Equal(len(list.Items), 2, fmt.Sprintf("expected 2 items but got %d", len(list.Items)))

	err = cliNameSpaceList(testClient)
	require.NoError(err)
}

func TestNameSpaceRemove(t *testing.T) {
	require := require.New(t)
	//assert := assert.New(t)

	testClient := fake.NewSimpleClientset()

	// Try removing non existant namespace
	err := cliNameSpaceRemove("test-space-1", testClient)
	require.Error(err)

	newNamespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-space-1",
			Labels: map[string]string{
				"marblerun/inject":     "enabled",
				"marblerun/inject-sgx": "enabled",
			},
		},
	}
	_, err = testClient.CoreV1().Namespaces().Create(context.TODO(), newNamespace1, metav1.CreateOptions{})
	require.NoError(err)

	// Remove namespace from mesh
	err = cliNameSpaceRemove("test-space-1", testClient)
	require.NoError(err)

	// Try removing namespace that is not labeled
	err = cliNameSpaceRemove("test-space-1", testClient)
	require.Error(err)

	newNamespace2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-space-2",
			Labels: map[string]string{
				"marblerun/inject":     "wrong-value",
				"marblerun/inject-sgx": "enabled",
			},
		},
	}
	_, err = testClient.CoreV1().Namespaces().Create(context.TODO(), newNamespace2, metav1.CreateOptions{})
	require.NoError(err)

	// Try removing namespace with incorrect label
	err = cliNameSpaceRemove("test-space-2", testClient)
	require.Error(err)
}
