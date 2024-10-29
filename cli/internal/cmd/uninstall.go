/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

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

// NewUninstallCmd returns the uninstall command.
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

func runUninstall(cmd *cobra.Command, _ []string) error {
	namespace, err := cmd.Flags().GetString("namespace")
	if err != nil {
		return err
	}

	kubeClient, err := kube.NewClient()
	if err != nil {
		return err
	}
	helmClient, err := helm.New(namespace)
	if err != nil {
		return err
	}
	return cliUninstall(cmd, helmClient, kubeClient, namespace)
}

// cliUninstall uninstalls MarbleRun.
func cliUninstall(
	cmd *cobra.Command, helmClient *helm.Client, kubeClient kubernetes.Interface, namespace string,
) error {
	wait, err := cmd.Flags().GetBool("wait")
	if err != nil {
		return err
	}
	if err := helmClient.Uninstall(wait); err != nil {
		return err
	}

	// If we get a "not found" error the resource was already removed / never created
	// and we can continue on without a problem
	if err := cleanupSecrets(cmd.Context(), kubeClient, namespace); err != nil && !errors.IsNotFound(err) {
		return err
	}

	if err := cleanupCSR(cmd.Context(), kubeClient, namespace); err != nil && !errors.IsNotFound(err) {
		return err
	}

	cmd.Println("MarbleRun successfully removed from your cluster")

	return nil
}

// cleanupSecrets removes secretes set for the Admission Controller.
func cleanupSecrets(ctx context.Context, kubeClient kubernetes.Interface, namespace string) error {
	return kubeClient.CoreV1().Secrets(namespace).Delete(ctx, "marble-injector-webhook-certs", metav1.DeleteOptions{})
}

// cleanupCSR removes a potentially leftover CSR from the Admission Controller.
func cleanupCSR(ctx context.Context, kubeClient kubernetes.Interface, namespace string) error {
	// in case of kubernetes version < 1.19 no CSR was created by the install command
	isLegacy, err := checkLegacyKubernetesVersion(kubeClient)
	if err != nil {
		return err
	}
	if isLegacy {
		return nil
	}

	return kubeClient.CertificatesV1().CertificateSigningRequests().Delete(ctx, webhookDNSName(namespace), metav1.DeleteOptions{})
}
