package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNodeSupportsSGX(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	testClient := fake.NewSimpleClientset()

	// Test node not supporting SGX
	testNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "regular-node",
		},
	}
	_, err := testClient.CoreV1().Nodes().Create(context.TODO(), testNode, metav1.CreateOptions{})
	require.NoError(err)

	nodes, err := testClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	require.NoError(err)

	supportsSGX := nodeSupportsSGX(nodes.Items[0].Status.Capacity)
	assert.False(supportsSGX, "function returned true for nodes not supporting SGX")

	err = testClient.CoreV1().Nodes().Delete(context.TODO(), "regular-node", metav1.DeleteOptions{})
	require.NoError(err)

	// Test Intel Device Plugin
	intelSGXNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "intel-sgx-node",
		},
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				intelEnclave:   resource.MustParse("10"),
				intelEpc:       resource.MustParse("500"),
				intelProvision: resource.MustParse("10"),
			},
		},
	}
	_, err = testClient.CoreV1().Nodes().Create(context.TODO(), intelSGXNode, metav1.CreateOptions{})
	require.NoError(err)

	nodes, err = testClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	require.NoError(err)

	supportsSGX = nodeSupportsSGX(nodes.Items[0].Status.Capacity)
	assert.True(supportsSGX, "function returned false for nodes supporting SGX")

	err = testClient.CoreV1().Nodes().Delete(context.TODO(), "intel-sgx-node", metav1.DeleteOptions{})
	require.NoError(err)

	// test Azure Device Plugin
	azureSGXNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "azure-sgx-node",
		},
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				azureEpc: resource.MustParse("500"),
			},
		},
	}
	_, err = testClient.CoreV1().Nodes().Create(context.TODO(), azureSGXNode, metav1.CreateOptions{})
	require.NoError(err)

	nodes, err = testClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	require.NoError(err)

	supportsSGX = nodeSupportsSGX(nodes.Items[0].Status.Capacity)
	assert.True(supportsSGX, "function returned false for nodes supporting SGX")
}

func TestCliCheckSGXSupport(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	testClient := fake.NewSimpleClientset()

	testNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "regular-node",
		},
	}
	_, err := testClient.CoreV1().Nodes().Create(context.TODO(), testNode, metav1.CreateOptions{})
	require.NoError(err)

	_, err = testClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	require.NoError(err)

	err = cliCheckSGXSupport(testClient)
	assert.NoError(err)

	// Test node supporting SGX
	testNodeSGX := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "sgx-node",
		},
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				intelEnclave:   resource.MustParse("10"),
				intelEpc:       resource.MustParse("500"),
				intelProvision: resource.MustParse("10"),
			},
		},
	}
	_, err = testClient.CoreV1().Nodes().Create(context.TODO(), testNodeSGX, metav1.CreateOptions{})
	require.NoError(err)

	err = cliCheckSGXSupport(testClient)
	assert.NoError(err)

	testNodeSGX.ObjectMeta.Name = "sgx-node-2"
	_, err = testClient.CoreV1().Nodes().Create(context.TODO(), testNodeSGX, metav1.CreateOptions{})
	require.NoError(err)

	err = cliCheckSGXSupport(testClient)
	assert.NoError(err)
}
