// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/edgelesssys/marblerun/cli/internal/helm"
	"github.com/edgelesssys/marblerun/cli/internal/kube"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func NewCheckCmd() *cobra.Command {
	var timeout uint

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check the status of MarbleRun's control plane",
		Long:  `Check the status of MarbleRun's control plane`,
		Args:  cobra.NoArgs,
		RunE: func(cobracmd *cobra.Command, args []string) error {
			kubeClient, err := kube.NewClient()
			if err != nil {
				return err
			}
			return cliCheck(kubeClient, timeout)
		},
	}

	cmd.Flags().UintVar(&timeout, "timeout", 60, "Time to wait before aborting in seconds")
	return cmd
}

// cliCheck if MarbleRun control-plane deployments are ready to use.
func cliCheck(kubeClient kubernetes.Interface, timeout uint) error {
	if err := checkDeploymentStatus(kubeClient, helm.InjectorDeployment, helm.Namespace, timeout); err != nil {
		return err
	}

	if err := checkDeploymentStatus(kubeClient, helm.CoordinatorDeployment, helm.Namespace, timeout); err != nil {
		return err
	}

	return nil
}

// checkDeploymentStatus checks if a deployment is installed on the cluster.
// If it is, this function will wait until all replicas have the "available" status (ready for at least minReadySeconds).
// Current status is continuously printed on screen.
func checkDeploymentStatus(kubeClient kubernetes.Interface, deploymentName string, namespace string, timeout uint) error {
	_, err := kubeClient.AppsV1().Deployments(namespace).Get(context.TODO(), deploymentName, metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	if errors.IsNotFound(err) {
		fmt.Printf("%s is not installed on this cluster\n", deploymentName)
	} else {
		deploymentReady := false
		var tries uint
		var podsReady string

		// check if command is run from a terminal
		isTTY := false
		if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) != 0 {
			isTTY = true
			// save current cursor position
			fmt.Print("\033[s")
		}

		for !deploymentReady && tries < timeout {
			deploymentReady, podsReady, err = deploymentIsReady(kubeClient, deploymentName, namespace)
			if err != nil {
				return err
			}

			// if command was run from a terminal we can print continuous updates on the same line
			if isTTY {
				// return cursor and clear line
				fmt.Print("\033[u\033[K")
				fmt.Printf("%s pods ready: %s", deploymentName, podsReady)
			} else {
				fmt.Printf("%s pods ready: %s\n", deploymentName, podsReady)
			}

			tries++
			time.Sleep(1 * time.Second)
		}
		fmt.Println()

		if tries == timeout {
			return fmt.Errorf("deployment %s was not ready after %d seconds (%s pods available) ", deploymentName, timeout, podsReady)
		}
	}

	return nil
}

// deploymentIsReady checks on the status of a single deployment and returns the number of available pods in the form "available/total".
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
