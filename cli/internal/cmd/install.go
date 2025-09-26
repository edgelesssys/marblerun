/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/cert-manager/cert-manager/pkg/util/cmapichecker"
	"github.com/edgelesssys/marblerun/cli/internal/helm"
	"github.com/edgelesssys/marblerun/cli/internal/kube"
	"github.com/edgelesssys/marblerun/util/k8sutil"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// NewInstallCmd returns the install command.
func NewInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Installs MarbleRun on a Kubernetes cluster",
		Long:  `Installs MarbleRun on a Kubernetes cluster`,
		Example: `# Install MarbleRun in simulation mode
marblerun install --simulation

# Install MarbleRun using a custom PCCS
marblerun install --dcap-pccs-url https://pccs.example.com/sgx/certification/v4/ --dcap-secure-cert FALSE`,
		Args: cobra.NoArgs,
		RunE: runInstall,
	}

	cmd.Flags().StringSlice("domain", []string{}, "Sets additional DNS names and IPs for the Coordinator TLS certificate")
	cmd.Flags().String("marblerun-chart-path", "", "Path to MarbleRun helm chart")
	cmd.Flags().String("version", "", "Version of the Coordinator to install, latest by default")
	cmd.Flags().String("resource-key", "", "Resource providing SGX, different depending on used device plugin. Use this to set tolerations/resources if your device plugin is not supported by MarbleRun")
	cmd.Flags().String("dcap-qpl", "azure", `Quote provider library to use by the Coordinator. One of {"azure", "intel"}`)
	cmd.Flags().String("dcap-qcnl-config-file", "", "Path to a custom QCNL configuration file. Mutually exclusive with \"--dcap-pccs-url\" and \"--dcap-secure-cert\".")
	cmd.Flags().String("dcap-pccs-url", "https://global.acccache.azure.net/sgx/certification/v4/", "Provisioning Certificate Caching Service (PCCS) server address. Defaults to Azure PCCS. Mutually exclusive with \"--dcap-qcnl-config-file\"")
	cmd.Flags().String("dcap-secure-cert", "TRUE", "To accept insecure HTTPS certificate from the PCCS, set this option to FALSE. Mutually exclusive with \"--dcap-qcnl-config-file\"")
	cmd.Flags().String("enterprise-access-token", "", "Access token for Enterprise Coordinator. Leave empty for default installation")
	cmd.Flags().Bool("simulation", false, "Set MarbleRun to start in simulation mode")
	cmd.Flags().Bool("disable-auto-injection", false, "Install MarbleRun without auto-injection webhook")
	cmd.Flags().Bool("wait", false, "Wait for MarbleRun installation to complete before returning")
	cmd.Flags().Int("mesh-server-port", 2001, "Set the mesh server port. Needs to be configured to the same port as in the data-plane marbles")
	cmd.Flags().Int("client-server-port", 4433, "Set the client server port. Needs to be configured to the same port as in your client tool stack")

	cmd.MarkFlagsMutuallyExclusive("dcap-qcnl-config-file", "dcap-pccs-url")
	cmd.MarkFlagsMutuallyExclusive("dcap-qcnl-config-file", "dcap-secure-cert")

	must(cmd.Flags().MarkDeprecated("dcap-qpl", "All platforms use the same QPL now. Use --dcap-pccs-url to configure the PCCS server address."))

	return cmd
}

func runInstall(cmd *cobra.Command, _ []string) error {
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
	cmChecker, err := kube.NewCertManagerChecker()
	if err != nil {
		return err
	}

	return cliInstall(cmd, helmClient, kubeClient, cmChecker, namespace)
}

// cliInstall installs MarbleRun on the cluster.
func cliInstall(cmd *cobra.Command, helmClient *helm.Client, kubeClient kubernetes.Interface, cmChecker cmapichecker.Interface, namespace string) error {
	flags, err := parseInstallFlags(cmd)
	if err != nil {
		return fmt.Errorf("parsing install flags: %w", err)
	}

	chart, err := helmClient.GetChart(flags.chartPath, flags.version)
	if err != nil {
		return fmt.Errorf("loading MarbleRun helm chart: %w", err)
	}

	if flags.resourceKey == "" {
		flags.resourceKey, err = getSGXResourceKey(cmd.Context(), kubeClient)
		if err != nil {
			return fmt.Errorf("trying to determine SGX resource key: %w", err)
		}
	}

	// verify namespace exists, if not create it
	if err := verifyNamespace(cmd.Context(), namespace, kubeClient); err != nil {
		return err
	}

	var webhookSettings []string
	if !flags.disableInjection {
		webhookSettings, err = installWebhookCerts(cmd, kubeClient, cmChecker, namespace)
		if err != nil {
			return errorAndCleanup(cmd.Context(), fmt.Errorf("installing webhook certs: %w", err), kubeClient, namespace)
		}
	}

	values, err := helm.UpdateValues(
		helm.Options{
			Hostname:            flags.hostname,
			QCNLConfigFile:      flags.qcnlConfigFile,
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
		return errorAndCleanup(cmd.Context(), fmt.Errorf("generating helm values: %w", err), kubeClient, namespace)
	}

	if err := helmClient.Install(cmd.Context(), flags.wait, chart, values); err != nil {
		return errorAndCleanup(cmd.Context(), fmt.Errorf("installing MarbleRun: %w", err), kubeClient, namespace)
	}

	cmd.Println("MarbleRun installed successfully")
	return nil
}

// installWebhookCerts sets up TLS certificates and keys required by MarbleRun's mutating admission webhook.
// Depending on the cluster, either a certificate issued by cert-manager or a self-created certificate using the Kubernetes API is used.
func installWebhookCerts(cmd *cobra.Command, kubeClient kubernetes.Interface, cmChecker cmapichecker.Interface, namespace string) ([]string, error) {
	cmd.Print("Setting up MarbleRun Webhook")

	if err := cmChecker.Check(cmd.Context()); err == nil {
		cmd.Printf("... Done\n")
		return []string{
			fmt.Sprintf("marbleInjector.start=%t", true),
			fmt.Sprintf("marbleInjector.useCertManager=%t", true),
		}, nil
	}

	certificateHandler, err := getCertificateHandler(cmd.OutOrStdout(), kubeClient, namespace)
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

	if err := createSecret(cmd.Context(), namespace, certificateHandler.getKey(), cert, kubeClient); err != nil {
		return nil, err
	}
	cmd.Printf(" Done\n")
	return injectorValues, nil
}

// createSecret creates a secret containing the signed certificate and private key for the webhook server.
func createSecret(ctx context.Context, namespace string, privKey *rsa.PrivateKey, crt []byte, kubeClient kubernetes.Interface) error {
	rsaPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		},
	)

	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "marble-injector-webhook-certs",
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"tls.crt": crt,
			"tls.key": rsaPEM,
		},
	}

	_, err := kubeClient.CoreV1().Secrets(namespace).Create(ctx, newSecret, metav1.CreateOptions{})
	return err
}

func getCertificateHandler(out io.Writer, kubeClient kubernetes.Interface, namespace string) (certificateInterface, error) {
	isLegacy, err := checkLegacyKubernetesVersion(kubeClient)
	if err != nil {
		return nil, err
	}
	if isLegacy {
		fmt.Fprintf(out, "\nKubernetes version lower than 1.19 detected, using self-signed certificates as CABundle")
		return newCertificateLegacy(namespace)
	}
	return newCertificateV1(kubeClient, namespace)
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
func errorAndCleanup(ctx context.Context, err error, kubeClient kubernetes.Interface, namespace string) error {
	// We dont care about any additional errors here
	_ = cleanupCSR(ctx, kubeClient, namespace)
	_ = cleanupSecrets(ctx, kubeClient, namespace)
	return err
}

type installFlags struct {
	chartPath        string
	hostname         []string
	version          string
	resourceKey      string
	qcnlConfigFile   string
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
	hostname, err := cmd.Flags().GetStringSlice("domain")
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
	qcnlConfigFile, err := cmd.Flags().GetString("dcap-qcnl-config-file")
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

	if accessToken != "" && chartPath == "" {
		return installFlags{}, fmt.Errorf("--marblerun-chart-path is required when using an enterprise access token")
	}

	return installFlags{
		chartPath:        chartPath,
		hostname:         hostname,
		version:          version,
		resourceKey:      resourceKey,
		qcnlConfigFile:   qcnlConfigFile,
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
