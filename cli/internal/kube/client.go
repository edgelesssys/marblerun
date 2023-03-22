// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package kube

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/edgelesssys/marblerun/cli/internal/helm"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const versionLabel = "app.kubernetes.io/version"

// NewClient returns the kubernetes Clientset to interact with the k8s API.
func NewClient() (*kubernetes.Clientset, error) {
	path := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	if path == "" {
		homedir, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(homedir, clientcmd.RecommendedHomeDir, clientcmd.RecommendedFileName)
	}

	kubeConfig, err := clientcmd.BuildConfigFromFlags("", path)
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
func CoordinatorVersion(ctx context.Context) (string, error) {
	kubeClient, err := NewClient()
	if err != nil {
		return "", err
	}

	coordinatorDeployment, err := kubeClient.AppsV1().Deployments(helm.Namespace).Get(ctx, helm.CoordinatorDeployment, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("retrieving deployment information: %w", err)
	}

	version := coordinatorDeployment.Labels[versionLabel]
	if len(version) <= 0 {
		return "", fmt.Errorf("deployment has no label %s", versionLabel)
	}
	return version, nil
}
