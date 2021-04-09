package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func newCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check the status of Marbleruns control plane",
		Long:  `Check the status of Marbleruns control plane`,
		Args:  cobra.NoArgs,
		RunE: func(cobracmd *cobra.Command, args []string) error {
			kubeClient, err := getKubernetesInterface()
			if err != nil {
				return err
			}
			return cliCheck(kubeClient)
		},
		SilenceUsage: true,
	}

	return cmd
}

// check if marblerun control-plane deployments are ready to use
func cliCheck(kubeClient kubernetes.Interface) error {
	err := checkDeploymentStatus(kubeClient, "marble-injector", "marblerun")
	if err != nil {
		return err
	}

	err = checkDeploymentStatus(kubeClient, "marblerun-coordinator", "marblerun")
	if err != nil {
		return err
	}

	// Add checks for other control plane deployments here
	//
	// err = checkDeploymentStatus(kubeClient, "some-control-plane-component", "marblerun")
	//

	return nil
}

// checkDeploymentStatus checks if a deployment is installed on the cluster
// If it is, this function will wait until all replicas have the "available" status (ready for at least minReadySeconds)
// Current status is continuously printed on screen
func checkDeploymentStatus(kubeClient kubernetes.Interface, deploymentName string, namespace string) error {
	_, err := kubeClient.AppsV1().Deployments(namespace).Get(context.TODO(), deploymentName, metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	if errors.IsNotFound(err) {
		fmt.Printf("%s is not installed on this cluster\n", deploymentName)
	} else {
		var podsReady string
		deploymentReady := false
		for !deploymentReady {
			deploymentReady, podsReady, err = deploymentIsReady(kubeClient, deploymentName, namespace)
			if err != nil {
				return err
			}

			updateString := fmt.Sprintf("%s pods ready: %s", deploymentName, podsReady)
			for i := 0; i < len(updateString); i++ {
				fmt.Printf(" ")
			}

			fmt.Printf("\r%s", updateString)
			time.Sleep(1)
		}
		fmt.Println()
	}

	return nil
}

// deploymentIsReady checks on the status of a single deployment and returns the number of available pods in the form "available/total"
func deploymentIsReady(kubeClient kubernetes.Interface, deploymentName string, namespace string) (bool, string, error) {
	deployment, err := kubeClient.AppsV1().Deployments(namespace).Get(context.TODO(), deploymentName, metav1.GetOptions{})
	if err != nil {
		return false, "", err
	}

	status := fmt.Sprintf("%d/%d", deployment.Status.AvailableReplicas, deployment.Status.Replicas)
	if deployment.Status.Replicas == deployment.Status.AvailableReplicas {
		return true, status, nil
	}

	return false, status, nil
}
