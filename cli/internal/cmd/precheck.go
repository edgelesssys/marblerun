// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"github.com/edgelesssys/marblerun/cli/internal/kube"
	"github.com/edgelesssys/marblerun/util/k8sutil"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func NewPrecheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "precheck",
		Short: "Check if your Kubernetes cluster supports SGX",
		Long:  `Check if your Kubernetes cluster supports SGX`,
		Args:  cobra.NoArgs,
		RunE:  runPrecheck,
	}

	return cmd
}

func runPrecheck(cmd *cobra.Command, args []string) error {
	kubeClient, err := kube.NewClient()
	if err != nil {
		return err
	}
	return cliCheckSGXSupport(cmd, kubeClient)
}

func cliCheckSGXSupport(cmd *cobra.Command, kubeClient kubernetes.Interface) error {
	nodes, err := kubeClient.CoreV1().Nodes().List(cmd.Context(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	supportedNodes := 0

	// Iterate over all nodes in the cluster and check their SGX support
	for _, node := range nodes.Items {
		if nodeSupportsSGX(node.Status.Capacity) {
			supportedNodes++
		}
	}

	if supportedNodes == 0 {
		cmd.Println("Cluster does not support SGX, you may still run MarbleRun in simulation mode")
		cmd.Println("To install MarbleRun run [marblerun install --simulation]")
		cmd.Println("If your nodes have SGX support you might be missing an SGX device plugin")
		cmd.Println("Check https://edglss.cc/doc-mr-k8s-prereq for more information")
	} else {
		nodeString := "node"
		if supportedNodes > 1 {
			nodeString = nodeString + "s"
		}
		cmd.Printf("Cluster supports SGX on %d %s\n", supportedNodes, nodeString)
		cmd.Println("To install MarbleRun run [marblerun install]")
	}

	return nil
}

// nodeSupportsSGX checks if a single cluster node supports SGX in some way.
// Checks for different implementations of SGX device plugins should be put here (e.g. different resource definitions than the one used by Azure/Intel).
func nodeSupportsSGX(capacityInfo corev1.ResourceList) bool {
	return nodeHasAlibabaDevPlugin(capacityInfo) || nodeHasAzureDevPlugin(capacityInfo) || nodeHasIntelDevPlugin(capacityInfo)
}

// nodeHasAlibabaDevPlugin checks if a node has the Alibaba device plugin installed (https://github.com/AliyunContainerService/sgx-device-plugin).
func nodeHasAlibabaDevPlugin(capacityInfo corev1.ResourceList) bool {
	epcQuant := capacityInfo[k8sutil.AlibabaEpc]
	return epcQuant.Value() != 0
}

// nodeHasAzureDevPlugin checks if a node has the Azures SGX device plugin installed (https://github.com/Azure/aks-engine/blob/master/docs/topics/sgx.md#deploying-the-sgx-device-plugin).
func nodeHasAzureDevPlugin(capacityInfo corev1.ResourceList) bool {
	epcQuant := capacityInfo[k8sutil.AzureEpc]
	return epcQuant.Value() != 0
}

// nodeHasIntelDevPlugin checks if a node has the Intel SGX device plugin installed (https://github.com/intel/intel-device-plugins-for-kubernetes#sgx-device-plugin).
func nodeHasIntelDevPlugin(capacityInfo corev1.ResourceList) bool {
	epcQuant := capacityInfo[k8sutil.IntelEpc]
	enclaveQuant := capacityInfo[k8sutil.IntelEnclave]
	provisionQuant := capacityInfo[k8sutil.IntelProvision]
	return !(epcQuant.Value() == 0 || enclaveQuant.Value() == 0 || provisionQuant.Value() == 0)
}
