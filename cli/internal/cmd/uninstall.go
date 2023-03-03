// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"context"

	"github.com/edgelesssys/marblerun/cli/internal/helm"
	"github.com/edgelesssys/marblerun/cli/internal/kube"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func NewUninstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove MarbleRun from a Kubernetes cluster",
		Long:  `Remove MarbleRun from a Kubernetes cluster`,
		Args:  cobra.NoArgs,
		RunE:  runUninstall,
	}

	cmd.Flags().Bool("wait", false, "Wait for the uninstallation to complete before returning")

	return cmd
}

func runUninstall(cmd *cobra.Command, args []string) error {
	kubeClient, err := kube.NewClient()
	if err != nil {
		return err
	}
	helmClient, err := helm.New()
	if err != nil {
		return err
	}
	return cliUninstall(cmd, helmClient, kubeClient)
}

// cliUninstall uninstalls MarbleRun.
func cliUninstall(cmd *cobra.Command, helmClient *helm.Client, kubeClient kubernetes.Interface) error {
	wait, err := cmd.Flags().GetBool("wait")
	if err != nil {
		return err
	}
	if err := helmClient.Uninstall(wait); err != nil {
		return err
	}

	// If we get a "not found" error the resource was already removed / never created
	// and we can continue on without a problem
	if err := cleanupSecrets(cmd.Context(), kubeClient); err != nil && !errors.IsNotFound(err) {
		return err
	}

	if err := cleanupCSR(cmd.Context(), kubeClient); err != nil && !errors.IsNotFound(err) {
		return err
	}

	cmd.Println("MarbleRun successfully removed from your cluster")

	return nil
}

// cleanupSecrets removes secretes set for the Admission Controller.
func cleanupSecrets(ctx context.Context, kubeClient kubernetes.Interface) error {
	return kubeClient.CoreV1().Secrets(helm.Namespace).Delete(ctx, "marble-injector-webhook-certs", metav1.DeleteOptions{})
}

// cleanupCSR removes a potentially leftover CSR from the Admission Controller.
func cleanupCSR(ctx context.Context, kubeClient kubernetes.Interface) error {
	// in case of kubernetes version < 1.19 no CSR was created by the install command
	isLegacy, err := checkLegacyKubernetesVersion(kubeClient)
	if err != nil {
		return err
	}
	if isLegacy {
		return nil
	}

	return kubeClient.CertificatesV1().CertificateSigningRequests().Delete(ctx, webhookName, metav1.DeleteOptions{})
}
