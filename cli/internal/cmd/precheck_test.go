// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"context"
	"testing"

	"github.com/edgelesssys/marblerun/util/k8sutil"
	"github.com/spf13/cobra"
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
	ctx := context.Background()

	_, err := testClient.CoreV1().Nodes().Create(ctx, testNode, metav1.CreateOptions{})
	require.NoError(err)

	nodes, err := testClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	require.NoError(err)

	supportsSGX := nodeSupportsSGX(nodes.Items[0].Status.Capacity)
	assert.False(supportsSGX, "function returned true for nodes not supporting SGX")

	err = testClient.CoreV1().Nodes().Delete(ctx, "regular-node", metav1.DeleteOptions{})
	require.NoError(err)

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
	_, err = testClient.CoreV1().Nodes().Create(ctx, intelSGXNode, metav1.CreateOptions{})
	require.NoError(err)

	nodes, err = testClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	require.NoError(err)

	supportsSGX = nodeSupportsSGX(nodes.Items[0].Status.Capacity)
	assert.True(supportsSGX, "function returned false for nodes supporting SGX")

	err = testClient.CoreV1().Nodes().Delete(ctx, "intel-sgx-node", metav1.DeleteOptions{})
	require.NoError(err)

	// test Azure Device Plugin
	azureSGXNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "azure-sgx-node",
		},
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				k8sutil.AzureEpc: resource.MustParse("500"),
			},
		},
	}
	_, err = testClient.CoreV1().Nodes().Create(ctx, azureSGXNode, metav1.CreateOptions{})
	require.NoError(err)

	nodes, err = testClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	require.NoError(err)

	supportsSGX = nodeSupportsSGX(nodes.Items[0].Status.Capacity)
	assert.True(supportsSGX, "function returned false for nodes supporting SGX")
}

func TestCliCheckSGXSupport(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	testClient := fake.NewSimpleClientset()

	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)

	testNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "regular-node",
		},
	}
	ctx := context.Background()

	_, err := testClient.CoreV1().Nodes().Create(ctx, testNode, metav1.CreateOptions{})
	require.NoError(err)

	_, err = testClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	require.NoError(err)

	err = cliCheckSGXSupport(cmd, testClient)
	assert.NoError(err)
	assert.Contains(out.String(), "--simulation")
	out.Reset()

	// Test node supporting SGX
	testNodeSGX := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "sgx-node",
		},
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				k8sutil.IntelEnclave:   resource.MustParse("10"),
				k8sutil.IntelEpc:       resource.MustParse("500"),
				k8sutil.IntelProvision: resource.MustParse("10"),
			},
		},
	}
	_, err = testClient.CoreV1().Nodes().Create(ctx, testNodeSGX, metav1.CreateOptions{})
	require.NoError(err)

	err = cliCheckSGXSupport(cmd, testClient)
	assert.NoError(err)
	assert.Contains(out.String(), "1 node")
	out.Reset()

	testNodeSGX.ObjectMeta.Name = "sgx-node-2"
	_, err = testClient.CoreV1().Nodes().Create(ctx, testNodeSGX, metav1.CreateOptions{})
	require.NoError(err)

	err = cliCheckSGXSupport(cmd, testClient)
	assert.NoError(err)
	assert.Contains(out.String(), "2 nodes")
	out.Reset()
}
