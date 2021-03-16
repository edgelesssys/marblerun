package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func newUninstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Removes Marblerun from a kubernetes cluster",
		Long:  `Removes Marblerun from a kubernetes cluster`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			settings := cli.New()
			kubeClient, err := getKubernetesInterface()
			if err != nil {
				return fmt.Errorf("failed setting up kubernetes client: %v", err)
			}
			return cliUninstall(settings, kubeClient)
		},
		SilenceUsage: true,
	}

	return cmd
}

// cliUninstall uninstalls marblerun
func cliUninstall(settings *cli.EnvSettings, kubeClient kubernetes.Interface) error {
	if err := removeHelmRelease(settings); err != nil {
		return err
	}

	// If we get a "not found" error the resource was already removed / never created
	// and we can continue on without a problem
	err := cleanupSecrets(kubeClient)
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	err = cleanupCSR(kubeClient)
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	fmt.Println("Marblerun successfully removed from your cluster")

	return nil
}

// removeHelmRelease removes kubernetes resources installed using helm
func removeHelmRelease(settings *cli.EnvSettings) error {
	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(settings.RESTClientGetter(), "marblerun", os.Getenv("HELM_DRIVER"), debug); err != nil {
		return err
	}

	uninstallAction := action.NewUninstall(actionConfig)
	_, err := uninstallAction.Run("marblerun-coordinator")

	return err
}

// cleanupSecrets removes secretes set for the Admission Controller
func cleanupSecrets(kubeClient kubernetes.Interface) error {
	return kubeClient.CoreV1().Secrets("marblerun").Delete(context.TODO(), "marble-injector-webhook-certs", metav1.DeleteOptions{})
}

// cleanupCSR removes a potentially leftover CSR from the Admission Controller
func cleanupCSR(kubeClient kubernetes.Interface) error {
	// in case of kubernetes version < 1.19 no CSR was created by the install command
	versionInfo, err := kubeClient.Discovery().ServerVersion()
	if err != nil {
		return err
	}
	majorVersion, err := strconv.Atoi(versionInfo.Major)
	if err != nil {
		return err
	}
	minorVersion, err := strconv.Atoi(versionInfo.Minor)
	if err != nil {
		return err
	}
	if majorVersion == 1 && minorVersion < 19 {
		return nil
	}

	return kubeClient.CertificatesV1().CertificateSigningRequests().Delete(context.TODO(), webhookName, metav1.DeleteOptions{})
}
