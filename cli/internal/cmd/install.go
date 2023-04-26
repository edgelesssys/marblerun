// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/edgelesssys/marblerun/cli/internal/helm"
	"github.com/edgelesssys/marblerun/cli/internal/kube"
	"github.com/edgelesssys/marblerun/util/k8sutil"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func NewInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Installs MarbleRun on a Kubernetes cluster",
		Long:  `Installs MarbleRun on a Kubernetes cluster`,
		Example: `# Install MarbleRun in simulation mode
marblerun install --simulation

# Install MarbleRun using the Intel QPL and custom PCCS
marblerun install --dcap-qpl intel --dcap-pccs-url https://pccs.example.com/sgx/certification/v3/ --dcap-secure-cert FALSE`,
		Args: cobra.NoArgs,
		RunE: runInstall,
	}

	cmd.Flags().String("domain", "localhost", "Sets the CNAME for the Coordinator certificate")
	cmd.Flags().String("marblerun-chart-path", "", "Path to MarbleRun helm chart")
	cmd.Flags().String("version", "", "Version of the Coordinator to install, latest by default")
	cmd.Flags().String("resource-key", "", "Resource providing SGX, different depending on used device plugin. Use this to set tolerations/resources if your device plugin is not supported by MarbleRun")
	cmd.Flags().String("dcap-qpl", "azure", `Quote provider library to use by the Coordinator. One of {"azure", "intel"}`)
	cmd.Flags().String("dcap-pccs-url", "https://localhost:8081/sgx/certification/v3/", "Provisioning Certificate Caching Service (PCCS) server address")
	cmd.Flags().String("dcap-secure-cert", "TRUE", "To accept insecure HTTPS certificate from the PCCS, set this option to FALSE")
	cmd.Flags().String("enterprise-access-token", "", "Access token for Enterprise Coordinator. Leave empty for default installation")
	cmd.Flags().Bool("simulation", false, "Set MarbleRun to start in simulation mode")
	cmd.Flags().Bool("disable-auto-injection", false, "Install MarbleRun without auto-injection webhook")
	cmd.Flags().Bool("wait", false, "Wait for MarbleRun installation to complete before returning")
	cmd.Flags().Int("mesh-server-port", 2001, "Set the mesh server port. Needs to be configured to the same port as in the data-plane marbles")
	cmd.Flags().Int("client-server-port", 4433, "Set the client server port. Needs to be configured to the same port as in your client tool stack")

	return cmd
}

func runInstall(cmd *cobra.Command, args []string) error {
	kubeClient, err := kube.NewClient()
	if err != nil {
		return err
	}
	helmClient, err := helm.New()
	if err != nil {
		return err
	}

	return cliInstall(cmd, helmClient, kubeClient)
}

// cliInstall installs MarbleRun on the cluster.
func cliInstall(cmd *cobra.Command, helmClient *helm.Client, kubeClient kubernetes.Interface) error {
	flags, err := parseInstallFlags(cmd)
	if err != nil {
		return fmt.Errorf("parsing install flags: %w", err)
	}

	chart, err := helmClient.GetChart(flags.chartPath, flags.version, (flags.accessToken != ""))
	if err != nil {
		return fmt.Errorf("loading MarbleRun helm chart: %w", err)
	}

	if flags.resourceKey == "" {
		flags.resourceKey, err = getSGXResourceKey(cmd.Context(), kubeClient)
		if err != nil {
			return fmt.Errorf("trying to determine SGX resource key: %w", err)
		}
	}

	var webhookSettings []string
	if !flags.disableInjection {
		webhookSettings, err = installWebhook(cmd, kubeClient)
		if err != nil {
			return errorAndCleanup(cmd.Context(), fmt.Errorf("installing webhook certs: %w", err), kubeClient)
		}
	}

	values, err := helmClient.UpdateValues(
		helm.Options{
			Hostname:            flags.hostname,
			DCAPQPL:             flags.dcapQPL,
			PCCSURL:             flags.pccsURL,
			UseSecureCert:       flags.useSecureCert,
			AccessToken:         flags.accessToken,
			SGXResourceKey:      flags.resourceKey,
			WebhookSettings:     webhookSettings,
			SimulationMode:      flags.simulation,
			CoordinatorRESTPort: flags.clientPort,
			CoordinatorGRPCPort: flags.meshPort,
		},
		chart.Values,
	)
	if err != nil {
		return errorAndCleanup(cmd.Context(), fmt.Errorf("generating helm values: %w", err), kubeClient)
	}

	if err := helmClient.Install(cmd.Context(), flags.wait, chart, values); err != nil {
		return errorAndCleanup(cmd.Context(), fmt.Errorf("installing MarbleRun: %w", err), kubeClient)
	}

	cmd.Println("MarbleRun installed successfully")
	return nil
}

// installWebhook enables a mutating admission webhook to allow automatic injection of values into pods.
func installWebhook(cmd *cobra.Command, kubeClient kubernetes.Interface) ([]string, error) {
	// verify 'marblerun' namespace exists, if not create it
	if err := verifyNamespace(cmd.Context(), helm.Namespace, kubeClient); err != nil {
		return nil, err
	}

	cmd.Print("Setting up MarbleRun Webhook")
	certificateHandler, err := getCertificateHandler(cmd.OutOrStdout(), kubeClient)
	if err != nil {
		return nil, err
	}
	cmd.Print(".")
	if err := certificateHandler.signRequest(cmd.Context()); err != nil {
		return nil, err
	}
	cmd.Print(".")
	injectorValues, err := certificateHandler.setCaBundle()
	if err != nil {
		return nil, err
	}
	cert, err := certificateHandler.get(cmd.Context())
	if err != nil {
		return nil, err
	}
	if len(cert) <= 0 {
		return nil, fmt.Errorf("certificate was not signed by the CA")
	}
	cmd.Print(".")

	if err := createSecret(cmd.Context(), certificateHandler.getKey(), cert, kubeClient); err != nil {
		return nil, err
	}
	cmd.Printf(" Done\n")
	return injectorValues, nil
}

// createSecret creates a secret containing the signed certificate and private key for the webhook server.
func createSecret(ctx context.Context, privKey *rsa.PrivateKey, crt []byte, kubeClient kubernetes.Interface) error {
	rsaPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		},
	)

	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "marble-injector-webhook-certs",
			Namespace: helm.Namespace,
		},
		Data: map[string][]byte{
			"tls.crt": crt,
			"tls.key": rsaPEM,
		},
	}

	_, err := kubeClient.CoreV1().Secrets(helm.Namespace).Create(ctx, newSecret, metav1.CreateOptions{})
	return err
}

func getCertificateHandler(out io.Writer, kubeClient kubernetes.Interface) (certificateInterface, error) {
	isLegacy, err := checkLegacyKubernetesVersion(kubeClient)
	if err != nil {
		return nil, err
	}
	if isLegacy {
		fmt.Fprintf(out, "\nKubernetes version lower than 1.19 detected, using self-signed certificates as CABundle")
		return newCertificateLegacy()
	}
	return newCertificateV1(kubeClient)
}

func verifyNamespace(ctx context.Context, namespace string, kubeClient kubernetes.Interface) error {
	_, err := kubeClient.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		// if the namespace does not exist we create it

		if errors.IsNotFound(err) {
			marbleNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespace,
				},
			}
			if _, err := kubeClient.CoreV1().Namespaces().Create(ctx, marbleNamespace, metav1.CreateOptions{}); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	return nil
}

// getSGXResourceKey checks what device plugin is providing SGX on the cluster and returns the corresponding resource key.
func getSGXResourceKey(ctx context.Context, kubeClient kubernetes.Interface) (string, error) {
	nodes, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", err
	}

	for _, node := range nodes.Items {
		if nodeHasAlibabaDevPlugin(node.Status.Capacity) {
			return k8sutil.AlibabaEpc.String(), nil
		}
		if nodeHasAzureDevPlugin(node.Status.Capacity) {
			return k8sutil.AzureEpc.String(), nil
		}
		if nodeHasIntelDevPlugin(node.Status.Capacity) {
			return k8sutil.IntelEpc.String(), nil
		}
	}

	// assume cluster has the intel SGX device plugin by default
	return k8sutil.IntelEpc.String(), nil
}

// errorAndCleanup returns the given error and deletes resources which might have been created previously.
// This prevents secrets and CSRs to stay on the cluster after a failed installation attempt.
func errorAndCleanup(ctx context.Context, err error, kubeClient kubernetes.Interface) error {
	// We dont care about any additional errors here
	cleanupCSR(ctx, kubeClient)
	cleanupSecrets(ctx, kubeClient)
	return err
}

type installFlags struct {
	chartPath        string
	hostname         string
	version          string
	resourceKey      string
	dcapQPL          string
	pccsURL          string
	useSecureCert    string
	accessToken      string
	simulation       bool
	disableInjection bool
	wait             bool
	clientPort       int
	meshPort         int
}

func parseInstallFlags(cmd *cobra.Command) (installFlags, error) {
	chartPath, err := cmd.Flags().GetString("marblerun-chart-path")
	if err != nil {
		return installFlags{}, err
	}
	hostname, err := cmd.Flags().GetString("domain")
	if err != nil {
		return installFlags{}, err
	}
	version, err := cmd.Flags().GetString("version")
	if err != nil {
		return installFlags{}, err
	}
	resourceKey, err := cmd.Flags().GetString("resource-key")
	if err != nil {
		return installFlags{}, err
	}
	dcapQPL, err := cmd.Flags().GetString("dcap-qpl")
	if err != nil {
		return installFlags{}, err
	}
	pccsURL, err := cmd.Flags().GetString("dcap-pccs-url")
	if err != nil {
		return installFlags{}, err
	}
	useSecureCert, err := cmd.Flags().GetString("dcap-secure-cert")
	if err != nil {
		return installFlags{}, err
	}
	accessToken, err := cmd.Flags().GetString("enterprise-access-token")
	if err != nil {
		return installFlags{}, err
	}
	simulation, err := cmd.Flags().GetBool("simulation")
	if err != nil {
		return installFlags{}, err
	}
	disableInjection, err := cmd.Flags().GetBool("disable-auto-injection")
	if err != nil {
		return installFlags{}, err
	}
	wait, err := cmd.Flags().GetBool("wait")
	if err != nil {
		return installFlags{}, err
	}
	clientPort, err := cmd.Flags().GetInt("client-server-port")
	if err != nil {
		return installFlags{}, err
	}
	meshPort, err := cmd.Flags().GetInt("mesh-server-port")
	if err != nil {
		return installFlags{}, err
	}

	return installFlags{
		chartPath:        chartPath,
		hostname:         hostname,
		version:          version,
		resourceKey:      resourceKey,
		dcapQPL:          dcapQPL,
		pccsURL:          pccsURL,
		useSecureCert:    useSecureCert,
		accessToken:      accessToken,
		simulation:       simulation,
		disableInjection: disableInjection,
		wait:             wait,
		clientPort:       clientPort,
		meshPort:         meshPort,
	}, nil
}
