/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package kube

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cert-manager/cert-manager/pkg/util/cmapichecker"
	"github.com/edgelesssys/marblerun/cli/internal/helm"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const versionLabel = "app.kubernetes.io/version"

// NewClient returns the kubernetes Clientset to interact with the k8s API.
func NewClient() (*kubernetes.Clientset, error) {
	kubeConfig, err := getRestConfig()
	if err != nil {
		return nil, err
	}

	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}

	return kubeClient, nil
}

// CoordinatorVersion returns the version of the Coordinator deployment.
func CoordinatorVersion(ctx context.Context, namespace string) (string, error) {
	kubeClient, err := NewClient()
	if err != nil {
		return "", err
	}

	coordinatorDeployment, err := kubeClient.AppsV1().Deployments(namespace).Get(ctx, helm.CoordinatorDeployment, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("retrieving deployment information: %w", err)
	}

	version := coordinatorDeployment.Labels[versionLabel]
	if len(version) <= 0 {
		return "", fmt.Errorf("deployment has no label %s", versionLabel)
	}
	return version, nil
}

// NewCertManagerChecker checks if cert-manager is installed in the cluster.
func NewCertManagerChecker() (cmapichecker.Interface, error) {
	kubeConfig, err := getRestConfig()
	if err != nil {
		return nil, err
	}

	return cmapichecker.New(kubeConfig, "default")
}

func getRestConfig() (*rest.Config, error) {
	path := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	if path == "" {
		homedir, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(homedir, clientcmd.RecommendedHomeDir, clientcmd.RecommendedFileName)
	}

	return clientcmd.BuildConfigFromFlags("", path)
}
