package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	intelEpc       corev1.ResourceName = "sgx.intel.com/epc"
	intelEnclave   corev1.ResourceName = "sgx.intel.com/enclave"
	intelProvision corev1.ResourceName = "sgx.intel.com/provision"
	azureEpc       corev1.ResourceName = "kubernetes.azure.com/sgx_epc_mem_in_MiB"
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
		fmt.Println("Cluster does not support SGX, you may still run Marblerun in simulation mode")
		fmt.Println("To install Marblerun run [marblerun install --simulation]")
	} else {
		nodeString := "node"
		if supportedNodes > 1 {
			nodeString = nodeString + "s"
		}
		fmt.Printf("Cluster supports SGX on %d %s\n", supportedNodes, nodeString)
		fmt.Println("To install Marblerun run [marblerun install]")
	}

	return nil
}

// nodeSupportsSGX checks if a single cluster node supports SGX in some way
// Checks for different implementations of SGX device plugins should be put here (e.g. different resource definitions than the one used by Azure/Intel)
func nodeSupportsSGX(capacityInfo corev1.ResourceList) bool {
	if nodeHasAzureDevPlugin(capacityInfo) {
		return true
	}

	if nodeHasIntelDevPlugin(capacityInfo) {
		return true
	}

	return false
}

// nodeHasAzureDevPlugin checks if a node has the Azures SGX device plugin installed
func nodeHasAzureDevPlugin(capacityInfo corev1.ResourceList) bool {
	epcQuant := capacityInfo[azureEpc]
	if epcQuant.Value() == 0 {
		return false
	}
	return true
}

// nodeHasIntelDevPlugin checks if a node has the Intel SGX device plugin installed
func nodeHasIntelDevPlugin(capacityInfo corev1.ResourceList) bool {
	epcQuant := capacityInfo[intelEpc]
	enclaveQuant := capacityInfo[intelEnclave]
	provisionQuant := capacityInfo[intelProvision]
	if epcQuant.Value() == 0 || enclaveQuant.Value() == 0 || provisionQuant.Value() == 0 {
		return false
	}
	return true
}
