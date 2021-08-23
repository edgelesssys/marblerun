package cmd

import (
	"context"
	"fmt"

	"github.com/edgelesssys/marblerun/util"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func newPrecheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "precheck",
		Short: "Check if your kubernetes cluster supports SGX",
		Long:  `Check if your kubernetes cluster supports SGX`,
		Args:  cobra.NoArgs,
		RunE: func(cobracmd *cobra.Command, args []string) error {
			kubeClient, err := getKubernetesInterface()
			if err != nil {
				return err
			}
			return cliCheckSGXSupport(kubeClient)
		},
		SilenceUsage: true,
	}

	return cmd
}

func cliCheckSGXSupport(kubeClient kubernetes.Interface) error {
	nodes, err := kubeClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
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
		fmt.Println("Cluster does not support SGX, you may still run MarbleRun in simulation mode")
		fmt.Println("To install MarbleRun run [marblerun install --simulation]")
		fmt.Println("If your nodes have SGX support you might be missing an SGX device plugin")
		fmt.Println("Check https://edglss.cc/doc-mr-k8s-prereq for more information")
	} else {
		nodeString := "node"
		if supportedNodes > 1 {
			nodeString = nodeString + "s"
		}
		fmt.Printf("Cluster supports SGX on %d %s\n", supportedNodes, nodeString)
		fmt.Println("To install MarbleRun run [marblerun install]")
	}

	return nil
}

// nodeSupportsSGX checks if a single cluster node supports SGX in some way
// Checks for different implementations of SGX device plugins should be put here (e.g. different resource definitions than the one used by Azure/Intel)
func nodeSupportsSGX(capacityInfo corev1.ResourceList) bool {
	return nodeHasAlibabaDevPlugin(capacityInfo) || nodeHasAzureDevPlugin(capacityInfo) || nodeHasIntelDevPlugin(capacityInfo)
}

// nodeHasAlibabaDevPlugin checks if a node has the Alibaba device plugin installed (https://github.com/AliyunContainerService/sgx-device-plugin)
func nodeHasAlibabaDevPlugin(capacityInfo corev1.ResourceList) bool {
	epcQuant := capacityInfo[util.AlibabaEpc]
	return epcQuant.Value() != 0
}

// nodeHasAzureDevPlugin checks if a node has the Azures SGX device plugin installed (https://github.com/Azure/aks-engine/blob/master/docs/topics/sgx.md#deploying-the-sgx-device-plugin)
func nodeHasAzureDevPlugin(capacityInfo corev1.ResourceList) bool {
	epcQuant := capacityInfo[util.AzureEpc]
	return epcQuant.Value() != 0
}

// nodeHasIntelDevPlugin checks if a node has the Intel SGX device plugin installed (https://github.com/intel/intel-device-plugins-for-kubernetes#sgx-device-plugin)
func nodeHasIntelDevPlugin(capacityInfo corev1.ResourceList) bool {
	epcQuant := capacityInfo[util.IntelEpc]
	enclaveQuant := capacityInfo[util.IntelEnclave]
	provisionQuant := capacityInfo[util.IntelProvision]
	return !(epcQuant.Value() == 0 || enclaveQuant.Value() == 0 || provisionQuant.Value() == 0)
}
