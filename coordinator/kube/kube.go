/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// Package kube provides functions to create Kubernetes clients.
package kube

import (
	"fmt"
	"os"
	"sync"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"golang.org/x/sys/unix"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// initOnce is used to ensure that enclave initialization is only performed once.
var initOnce sync.Once

// GetClient returns a Kubernetes client using the in-cluster configuration.
func GetClient() (*kubernetes.Clientset, error) {
	// Set up enclave environment if necessary
	if err := initEnclave(); err != nil {
		return nil, err
	}

	// Create in-cluster Kubernetes config
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("creating in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	return clientset, nil
}

// initEnclave initializes the enclave by setting env variables and mounting the Kubernetes serviceaccount.
func initEnclave() error {
	var err error
	initOnce.Do(func() {
		// See the Kubernetes implementation for a reference: https://github.com/kubernetes/client-go/blob/v0.27.1/rest/config.go#L511
		// Invalid configurations will be caught when setting up the store
		os.Setenv(constants.EnvKubernetesServiceHost, os.Getenv("EDG_"+constants.EnvKubernetesServiceHost))
		os.Setenv(constants.EnvKubernetesServicePort, os.Getenv("EDG_"+constants.EnvKubernetesServicePort))

		// Mount Kubernetes serviceaccount from hostfs into the enclave
		const k8sDir = "/var/run/secrets/kubernetes.io"
		if err = unix.Mount(k8sDir, k8sDir, "oe_host_file_system", 0, ""); err != nil {
			err = fmt.Errorf("mounting %s into enclave: %w", k8sDir, err)
		}
	})

	return err
}
