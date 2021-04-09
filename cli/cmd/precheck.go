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

	numNodes := len(nodes.Items)
	supportedNodes := 0

	// Iterate over all nodes in the cluster and check their SGX support
	for i := 0; i < numNodes; i++ {
		if nodeSupportsSGX(nodes.Items[i].Status.Capacity) {
			supportedNodes++
		}
	}

	nodeString := "node"

	if supportedNodes == 0 {
		fmt.Println("Cluster does not support SGX, you may still run Marblerun in simulation mode")
		fmt.Println("To install Marblerun run [marblerun install --simulation]")
	} else {
		if supportedNodes > 1 {
			nodeString = nodeString + "s"
		}
		fmt.Printf("Cluster supports SGX on %d %s\n", supportedNodes, nodeString)
		fmt.Println("To install Marblerun run [marblerun install]")
	}

	return nil
}

// nodeSupportsSGX checks if a single cluster node supports SGX in some way
// Checks for different implementations of kubernetes SGX should be put here (e.g. different resource definitions than the one used by Azure)
func nodeSupportsSGX(capacityInfo corev1.ResourceList) bool {
	if nodeSupportsAzureSGX(capacityInfo) {
		return true
	}

	// if nodeSupports[SomeCloudProvider]SGX(capacityInfo) {
	// 	return true
	// }

	return false
}

// nodeSupportsAzureSGX checks if nodes in the cluster contain Azures SGX definitions
func nodeSupportsAzureSGX(capacityInfo corev1.ResourceList) bool {
	epcQuant := capacityInfo[intelEpc]
	enclaveQuant := capacityInfo[intelEnclave]
	provisionQuant := capacityInfo[intelProvision]
	if epcQuant.Value() == 0 || enclaveQuant.Value() == 0 || provisionQuant.Value() == 0 {
		return false
	}
	return true
}
