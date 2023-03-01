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
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/edgelesssys/marblerun/cli/internal/constants"
	"github.com/edgelesssys/marblerun/cli/internal/kube"
	"github.com/edgelesssys/marblerun/util"
	"github.com/gofrs/flock"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
	"helm.sh/helm/v3/pkg/strvals"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type installOptions struct {
	chartPath        string
	hostname         string
	version          string
	resourceKey      string
	dcapQpl          string
	pccsUrl          string
	useSecureCert    string
	accessToken      string
	simulation       bool
	disableInjection bool
	clientPort       int
	meshPort         int
	kubeClient       kubernetes.Interface
	settings         *cli.EnvSettings
}

func NewInstallCmd() *cobra.Command {
	options := &installOptions{}

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Installs MarbleRun on a Kubernetes cluster",
		Long:  `Installs MarbleRun on a Kubernetes cluster`,
		Example: `# Install MarbleRun in simulation mode
marblerun install --simulation

# Install MarbleRun using the Intel QPL and custom PCCS
marblerun install --dcap-qpl intel --dcap-pccs-url https://pccs.example.com/sgx/certification/v3/ --dcap-secure-cert FALSE`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options.settings = cli.New()
			var err error
			options.kubeClient, err = kube.NewClient()
			if err != nil {
				return err
			}

			return cliInstall(options)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&options.hostname, "domain", "localhost", "Sets the CNAME for the Coordinator certificate")
	cmd.Flags().StringVar(&options.chartPath, "marblerun-chart-path", "", "Path to MarbleRun helm chart")
	cmd.Flags().StringVar(&options.version, "version", "", "Version of the Coordinator to install, latest by default")
	cmd.Flags().StringVar(&options.resourceKey, "resource-key", "", "Resource providing SGX, different depending on used device plugin. Use this to set tolerations/resources if your device plugin is not supported by MarbleRun")
	cmd.Flags().StringVar(&options.dcapQpl, "dcap-qpl", "azure", `Quote provider library to use by the Coordinator. One of {"azure", "intel"}`)
	cmd.Flags().StringVar(&options.pccsUrl, "dcap-pccs-url", "https://localhost:8081/sgx/certification/v3/", "Provisioning Certificate Caching Service (PCCS) server address")
	cmd.Flags().StringVar(&options.useSecureCert, "dcap-secure-cert", "TRUE", "To accept insecure HTTPS certificate from the PCCS, set this option to FALSE")
	cmd.Flags().StringVar(&options.accessToken, "enterprise-access-token", "", "Access token for Enterprise Coordinator. Leave empty for default installation")
	cmd.Flags().BoolVar(&options.simulation, "simulation", false, "Set MarbleRun to start in simulation mode")
	cmd.Flags().BoolVar(&options.disableInjection, "disable-auto-injection", false, "Install MarbleRun without auto-injection webhook")
	cmd.Flags().IntVar(&options.meshPort, "mesh-server-port", 2001, "Set the mesh server port. Needs to be configured to the same port as in the data-plane marbles")
	cmd.Flags().IntVar(&options.clientPort, "client-server-port", 4433, "Set the client server port. Needs to be configured to the same port as in your client tool stack")

	return cmd
}

// cliInstall installs MarbleRun on the cluster.
func cliInstall(options *installOptions) error {
	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(options.settings.RESTClientGetter(), constants.HelmNamespace, os.Getenv("HELM_DRIVER"), debug); err != nil {
		return err
	}

	// create helm installer
	installer := action.NewInstall(actionConfig)
	installer.CreateNamespace = true
	installer.Namespace = constants.HelmNamespace
	installer.ReleaseName = constants.HelmRelease
	installer.ChartPathOptions.Version = options.version

	if options.chartPath == "" {
		// No chart was specified -> add or update edgeless helm repo
		err := getRepo(constants.HelmRepoName, constants.HelmRepoURI, options.settings)
		if err != nil {
			return err
		}

		// Enterprise chart is used if an access token is provided
		chartName := constants.HelmChartName
		if options.accessToken != "" {
			chartName = constants.HelmChartNameEnterprise
		}
		options.chartPath, err = installer.ChartPathOptions.LocateChart(chartName, options.settings)
		if err != nil {
			return err
		}
	}
	chart, err := loader.Load(options.chartPath)
	if err != nil {
		return err
	}

	var resourceKey string
	if len(options.resourceKey) <= 0 {
		resourceKey, err = getSGXResourceKey(options.kubeClient)
		if err != nil {
			return err
		}
	} else {
		resourceKey = options.resourceKey
	}

	// set overwrite values
	finalValues := map[string]interface{}{}
	stringValues := []string{}

	stringValues = append(stringValues, fmt.Sprintf("coordinator.meshServerPort=%d", options.meshPort))
	stringValues = append(stringValues, fmt.Sprintf("coordinator.clientServerPort=%d", options.clientPort))

	if options.simulation {
		// simulation mode, disable tolerations and resources, set simulation to true
		stringValues = append(stringValues,
			fmt.Sprintf("tolerations=%s", "null"),
			fmt.Sprintf("coordinator.simulation=%t", options.simulation),
			fmt.Sprintf("coordinator.resources.limits=%s", "null"),
			fmt.Sprintf("coordinator.hostname=%s", options.hostname),
			fmt.Sprintf("dcap=%s", "null"),
		)
	} else {
		stringValues = append(stringValues,
			fmt.Sprintf("coordinator.hostname=%s", options.hostname),
			fmt.Sprintf("dcap.qpl=%s", options.dcapQpl),
			fmt.Sprintf("dcap.pccsUrl=%s", options.pccsUrl),
			fmt.Sprintf("dcap.useSecureCert=%s", options.useSecureCert),
		)

		// Helms value merge function will overwrite any preset values for "tolerations" if we set new ones here
		// To avoid this we set the new toleration for "resourceKey" and copy all preset tolerations
		needToleration := true
		idx := 0
		for _, toleration := range chart.Values["tolerations"].([]interface{}) {
			if key, ok := toleration.(map[string]interface{})["key"]; ok {
				if key == resourceKey {
					needToleration = false
				}
				stringValues = append(stringValues, fmt.Sprintf("tolerations[%d].key=%v", idx, key))
			}
			if operator, ok := toleration.(map[string]interface{})["operator"]; ok {
				stringValues = append(stringValues, fmt.Sprintf("tolerations[%d].operator=%v", idx, operator))
			}
			if effect, ok := toleration.(map[string]interface{})["effect"]; ok {
				stringValues = append(stringValues, fmt.Sprintf("tolerations[%d].effect=%v", idx, effect))
			}
			if value, ok := toleration.(map[string]interface{})["value"]; ok {
				stringValues = append(stringValues, fmt.Sprintf("tolerations[%d].value=%v", idx, value))
			}
			if tolerationSeconds, ok := toleration.(map[string]interface{})["tolerationSeconds"]; ok {
				stringValues = append(stringValues, fmt.Sprintf("tolerations[%d].tolerationSeconds=%v", idx, tolerationSeconds))
			}
			idx++
		}
		if needToleration {
			stringValues = append(stringValues,
				fmt.Sprintf("tolerations[%d].key=%s", idx, resourceKey),
				fmt.Sprintf("tolerations[%d].operator=Exists", idx),
				fmt.Sprintf("tolerations[%d].effect=NoSchedule", idx),
			)
		}
	}

	// Configure enterprise access token
	if options.accessToken != "" {
		coordinatorCfg, ok := chart.Values["coordinator"].(map[string]interface{})
		if !ok {
			return errors.New("coordinator not found in chart values")
		}
		repository, ok := coordinatorCfg["repository"].(string)
		if !ok {
			return errors.New("coordinator.registry not found in chart values")
		}

		token := fmt.Sprintf(`{"auths":{"%s":{"auth":"%s"}}}`, repository, options.accessToken)
		stringValues = append(stringValues, fmt.Sprintf("pullSecret.token=%s", base64.StdEncoding.EncodeToString([]byte(token))))
	}

	if !options.disableInjection {
		injectorValues, err := installWebhook(options.kubeClient)
		if err != nil {
			return errorAndCleanup(err, options.kubeClient)
		}

		stringValues = append(stringValues, injectorValues...)
		stringValues = append(stringValues, fmt.Sprintf("marbleInjector.resourceKey=%s", resourceKey))
	}

	for _, val := range stringValues {
		if err := strvals.ParseInto(val, finalValues); err != nil {
			return errorAndCleanup(err, options.kubeClient)
		}
	}

	if !options.simulation {
		setSGXValues(resourceKey, finalValues, chart.Values)
	}

	if err := chartutil.ValidateAgainstSchema(chart, finalValues); err != nil {
		return errorAndCleanup(err, options.kubeClient)
	}

	if _, err := installer.Run(chart, finalValues); err != nil {
		return errorAndCleanup(err, options.kubeClient)
	}

	fmt.Println("MarbleRun installed successfully")
	return nil
}

// Simplified repo_add from helm cli to add MarbleRun repo if it does not yet exist.
// To make sure we use the newest chart we always download the needed index file.
func getRepo(name string, url string, settings *cli.EnvSettings) error {
	repoFile := settings.RepositoryConfig

	// Ensure the file directory exists as it is required for file locking
	err := os.MkdirAll(filepath.Dir(repoFile), 0o755)
	if err != nil && !os.IsExist(err) {
		return err
	}

	// Acquire a file lock for process synchronization
	fileLock := flock.New(strings.Replace(repoFile, filepath.Ext(repoFile), ".lock", 1))
	lockCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	locked, err := fileLock.TryLockContext(lockCtx, time.Second)
	if err == nil && locked {
		defer fileLock.Unlock()
	}
	if err != nil {
		return err
	}

	b, err := os.ReadFile(repoFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	var f repo.File
	if err := yaml.Unmarshal(b, &f); err != nil {
		return err
	}

	c := &repo.Entry{
		Name: name,
		URL:  url,
	}

	r, err := repo.NewChartRepository(c, helmgetter.All(settings))
	if err != nil {
		return err
	}

	if _, err := r.DownloadIndexFile(); err != nil {
		return errors.New("chart repository cannot be reached")
	}

	f.Update(c)

	if err := f.WriteFile(repoFile, 0o644); err != nil {
		return err
	}
	return nil
}

// installWebhook enables a mutating admission webhook to allow automatic injection of values into pods.
func installWebhook(kubeClient kubernetes.Interface) ([]string, error) {
	// verify 'marblerun' namespace exists, if not create it
	if err := verifyNamespace(constants.HelmNamespace, kubeClient); err != nil {
		return nil, err
	}

	fmt.Printf("Setting up MarbleRun Webhook")
	certificateHandler, err := getCertificateHandler(kubeClient)
	if err != nil {
		return nil, err
	}
	fmt.Printf(".")
	if err := certificateHandler.signRequest(); err != nil {
		return nil, err
	}
	fmt.Printf(".")
	injectorValues, err := certificateHandler.setCaBundle()
	if err != nil {
		return nil, err
	}
	cert, err := certificateHandler.get()
	if err != nil {
		return nil, err
	}
	if len(cert) <= 0 {
		return nil, fmt.Errorf("certificate was not signed by the CA")
	}
	fmt.Printf(".")

	if err := createSecret(certificateHandler.getKey(), cert, kubeClient); err != nil {
		return nil, err
	}
	fmt.Printf(" Done\n")
	return injectorValues, nil
}

// createSecret creates a secret containing the signed certificate and private key for the webhook server.
func createSecret(privKey *rsa.PrivateKey, crt []byte, kubeClient kubernetes.Interface) error {
	rsaPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		},
	)

	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "marble-injector-webhook-certs",
			Namespace: constants.HelmNamespace,
		},
		Data: map[string][]byte{
			"tls.crt": crt,
			"tls.key": rsaPEM,
		},
	}

	_, err := kubeClient.CoreV1().Secrets(constants.HelmNamespace).Create(context.TODO(), newSecret, metav1.CreateOptions{})
	return err
}

func getCertificateHandler(kubeClient kubernetes.Interface) (certificateInterface, error) {
	isLegacy, err := checkLegacyKubernetesVersion(kubeClient)
	if err != nil {
		return nil, err
	}
	if isLegacy {
		fmt.Printf("\nKubernetes version lower than 1.19 detected, using self-signed certificates as CABundle")
		return newCertificateLegacy()
	}
	return newCertificateV1(kubeClient)
}

func verifyNamespace(namespace string, kubeClient kubernetes.Interface) error {
	_, err := kubeClient.CoreV1().Namespaces().Get(context.TODO(), namespace, metav1.GetOptions{})
	if err != nil {
		// if the namespace does not exist we create it
		if err.Error() == fmt.Sprintf("namespaces \"%s\" not found", namespace) {
			marbleNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespace,
				},
			}
			if _, err := kubeClient.CoreV1().Namespaces().Create(context.TODO(), marbleNamespace, metav1.CreateOptions{}); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	return nil
}

// getSGXResourceKey checks what device plugin is providing SGX on the cluster and returns the corresponding resource key.
func getSGXResourceKey(kubeClient kubernetes.Interface) (string, error) {
	nodes, err := kubeClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return "", err
	}

	for _, node := range nodes.Items {
		if nodeHasAlibabaDevPlugin(node.Status.Capacity) {
			return util.AlibabaEpc.String(), nil
		}
		if nodeHasAzureDevPlugin(node.Status.Capacity) {
			return util.AzureEpc.String(), nil
		}
		if nodeHasIntelDevPlugin(node.Status.Capacity) {
			return util.IntelEpc.String(), nil
		}
	}

	// assume cluster has the intel SGX device plugin by default
	return util.IntelEpc.String(), nil
}

// setSGXValues sets the needed values for the coordinator as a map[string]interface.
// strvals can't parse keys which include dots, e.g. setting as a resource limit key "sgx.intel.com/epc" will lead to errors.
func setSGXValues(resourceKey string, values, chartValues map[string]interface{}) {
	values["coordinator"].(map[string]interface{})["resources"] = map[string]interface{}{
		"limits":   map[string]interface{}{},
		"requests": map[string]interface{}{},
	}

	var needNewLimit bool
	limit := util.GetEPCResourceLimit(resourceKey)

	// remove all previously set sgx resource limits
	if presetLimits, ok := chartValues["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["limits"].(map[string]interface{}); ok {
		for oldResourceKey := range presetLimits {
			// Make sure the key we delete is an unwanted sgx resource and not a custom resource or common resource (cpu, memory, etc.)
			if needsDeletion(oldResourceKey, resourceKey) {
				values["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["limits"].(map[string]interface{})[oldResourceKey] = nil
				needNewLimit = true
			}
		}
	}

	// remove all previously set sgx resource requests
	if presetLimits, ok := chartValues["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["requests"].(map[string]interface{}); ok {
		for oldResourceKey := range presetLimits {
			if needsDeletion(oldResourceKey, resourceKey) {
				values["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["requests"].(map[string]interface{})[oldResourceKey] = nil
				needNewLimit = true
			}
		}
	}

	// Set the new sgx resource limit, kubernetes will automatically set a resource request equal to the limit
	if needNewLimit {
		values["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["limits"].(map[string]interface{})[resourceKey] = limit
	}

	// Make sure provision and enclave bit is set if the Intel plugin is used
	if resourceKey == util.IntelEpc.String() {
		values["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["limits"].(map[string]interface{})[util.IntelProvision.String()] = 1
		values["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["limits"].(map[string]interface{})[util.IntelEnclave.String()] = 1
	}
}

// errorAndCleanup returns the given error and deletes resources which might have been created previously.
// This prevents secrets and CSRs to stay on the cluster after a failed installation attempt.
func errorAndCleanup(err error, kubeClient kubernetes.Interface) error {
	// We dont care about any additional errors here
	cleanupCSR(kubeClient)
	cleanupSecrets(kubeClient)
	return err
}

// needsDeletion checks if an existing key of a helm chart should be deleted.
// Choice is based on the resource key of the used SGX device plugin.
func needsDeletion(existingKey, sgxKey string) bool {
	sgxResources := []string{
		util.AlibabaEpc.String(), util.AzureEpc.String(), util.IntelEpc.String(),
		util.IntelProvision.String(), util.IntelEnclave.String(),
	}

	switch sgxKey {
	case util.AlibabaEpc.String(), util.AzureEpc.String():
		// Delete all non Alibaba/Azure SGX resources depending on the used SGX device plugin
		return sgxKey != existingKey && keyInList(existingKey, sgxResources)
	case util.IntelEpc.String():
		// Delete all non Intel SGX resources depending on the used SGX device plugin
		// Keep Intel provision and enclave bit
		return keyInList(existingKey, []string{util.AlibabaEpc.String(), util.AzureEpc.String()})
	default:
		// Either no SGX plugin or a custom SGX plugin is used
		// Delete all known SGX resources
		return keyInList(existingKey, sgxResources)
	}
}

func keyInList(key string, list []string) bool {
	for _, l := range list {
		if key == l {
			return true
		}
	}
	return false
}

func debug(format string, v ...interface{}) {
}
