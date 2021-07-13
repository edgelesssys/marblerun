package cmd

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/edgelesssys/marblerun/util"
	"github.com/gofrs/flock"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/getter"
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
	simulation       bool
	disableInjection bool
	clientPort       int
	meshPort         int
	kubeClient       kubernetes.Interface
	settings         *cli.EnvSettings
}

func newInstallCmd() *cobra.Command {
	options := &installOptions{}

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Installs marblerun on a kubernetes cluster",
		Long:  `Installs marblerun on a kubernetes cluster`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options.settings = cli.New()
			var err error
			options.kubeClient, err = getKubernetesInterface()
			if err != nil {
				return err
			}

			return cliInstall(options)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&options.hostname, "domain", "localhost", "Sets the CNAME for the Coordinator certificate")
	cmd.Flags().StringVar(&options.chartPath, "marblerun-chart-path", "", "Path to marblerun helm chart")
	cmd.Flags().StringVar(&options.version, "version", "", "Version of the Coordinator to install, latest by default")
	cmd.Flags().StringVar(&options.resourceKey, "resource-key", "", "Resource providing SGX, different depending on used device plugin. Use this to set tolerations/resources if your device plugin is not supported by marblerun")
	cmd.Flags().BoolVar(&options.simulation, "simulation", false, "Set marblerun to start in simulation mode")
	cmd.Flags().BoolVar(&options.disableInjection, "disable-auto-injection", false, "Disable automatic injection of selected namespaces")
	cmd.Flags().IntVar(&options.meshPort, "mesh-server-port", 2001, "Set the mesh server port. Needs to be configured to the same port as in the data-plane marbles")
	cmd.Flags().IntVar(&options.clientPort, "client-server-port", 4433, "Set the client server port. Needs to be configured to the same port as in your client tool stack")

	return cmd
}

// cliInstall installs marblerun on the cluster
func cliInstall(options *installOptions) error {
	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(options.settings.RESTClientGetter(), "marblerun", os.Getenv("HELM_DRIVER"), debug); err != nil {
		return err
	}

	// create helm installer
	installer := action.NewInstall(actionConfig)
	installer.CreateNamespace = true
	installer.Namespace = "marblerun"
	installer.ReleaseName = "marblerun-coordinator"
	installer.ChartPathOptions.Version = options.version

	if options.chartPath == "" {
		// No chart was specified -> add or update edgeless helm repo
		err := getRepo("edgeless", "https://helm.edgeless.systems/stable", options.settings)
		if err != nil {
			return err
		}
		options.chartPath, err = installer.ChartPathOptions.LocateChart("edgeless/marblerun-coordinator", options.settings)
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
		// simulation mode, disable tolerations and resources, set simulation to 1
		stringValues = append(stringValues,
			fmt.Sprintf("tolerations=%s", "null"),
			fmt.Sprintf("coordinator.simulation=%d", 1),
			fmt.Sprintf("coordinator.resources.limits=%s", "null"),
			fmt.Sprintf("coordinator.hostname=%s", options.hostname),
		)
	} else {
		stringValues = append(stringValues,
			fmt.Sprintf("coordinator.hostname=%s", options.hostname),
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

	fmt.Println("Marblerun installed successfully")
	return nil
}

// simplified repo_add from helm cli to add marblerun repo if it does not yet exist
// to make sure we use the newest chart we always download the needed index file
func getRepo(name string, url string, settings *cli.EnvSettings) error {
	repoFile := settings.RepositoryConfig

	// Ensure the file directory exists as it is required for file locking
	err := os.MkdirAll(filepath.Dir(repoFile), 0755)
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

	b, err := ioutil.ReadFile(repoFile)
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

	r, err := repo.NewChartRepository(c, getter.All(settings))
	if err != nil {
		return err
	}

	if _, err := r.DownloadIndexFile(); err != nil {
		return errors.New("chart repository cannot be reached")
	}

	f.Update(c)

	if err := f.WriteFile(repoFile, 0644); err != nil {
		return err
	}
	return nil
}

// installWebhook enables a mutating admission webhook to allow automatic injection of values into pods
func installWebhook(kubeClient kubernetes.Interface) ([]string, error) {
	// verify marblerun namespace exists, if not create it
	if err := verifyNamespace("marblerun", kubeClient); err != nil {
		return nil, err
	}

	fmt.Printf("Setting up Marblerun Webhook")
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

// createSecret creates a secret containing the signed certificate and private key for the webhook server
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
			Namespace: "marblerun",
		},
		Data: map[string][]byte{
			"cert.pem": crt,
			"key.pem":  rsaPEM,
		},
	}

	_, err := kubeClient.CoreV1().Secrets("marblerun").Create(context.TODO(), newSecret, metav1.CreateOptions{})
	return err
}

func getCertificateHandler(kubeClient kubernetes.Interface) (certificateInterface, error) {
	versionInfo, err := kubeClient.Discovery().ServerVersion()
	if err != nil {
		return nil, err
	}
	majorVersion, err := strconv.Atoi(versionInfo.Major)
	if err != nil {
		return nil, err
	}
	minorVersion, err := strconv.Atoi(versionInfo.Minor)
	if err != nil {
		return nil, err
	}

	// return the legacy interface if kubernetes version is < 1.19
	if majorVersion == 1 && minorVersion < 19 {
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

// getSGXResourceKey checks what device plugin is providing SGX on the cluster and returns the corresponding resource key
func getSGXResourceKey(kubeClient kubernetes.Interface) (string, error) {
	nodes, err := kubeClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return "", err
	}

	for _, node := range nodes.Items {
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

// setSGXValues sets the needed values for the coorindator as a map[string]interface
// strvals cant parse keys which include dots, e.g. setting as a resource limit key "sgx.intel.com/epc" will lead to errors
func setSGXValues(resourceKey string, values, chartValues map[string]interface{}) {
	values["coordinator"].(map[string]interface{})["resources"] = map[string]interface{}{
		"limits":   map[string]interface{}{},
		"requests": map[string]interface{}{},
	}

	toRemove := fmt.Sprintf("%s %s", util.IntelEpc.String(), util.AzureEpc.String())
	var needNewLimit bool
	limit := util.GetEPCResourceLimit(resourceKey)

	// remove all previously set sgx resource limits
	if presetLimits, ok := chartValues["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["limits"].(map[string]interface{}); ok {
		for oldResourceKey := range presetLimits {
			// Make sure the key we delete is an unwanted sgx resource and not a custom resource or common resource (cpu, memory, etc.)
			if oldResourceKey != resourceKey && strings.Contains(toRemove, oldResourceKey) {
				values["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["limits"].(map[string]interface{})[oldResourceKey] = nil
				needNewLimit = true
			}
		}
	}

	// remove all previously set sgx resource requests
	if presetLimits, ok := chartValues["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["requests"].(map[string]interface{}); ok {
		for oldResourceKey := range presetLimits {
			if oldResourceKey != resourceKey && strings.Contains(toRemove, oldResourceKey) {
				values["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["requests"].(map[string]interface{})[oldResourceKey] = nil
				needNewLimit = true
			}
		}
	}

	// Set the new sgx resource limit, kubernetes will automatically set a resource request equal to the limit
	if needNewLimit {
		values["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["limits"].(map[string]interface{})[resourceKey] = limit
	}

	// Make sure provision bit is set if the Intel plugin is used
	if resourceKey == util.IntelEpc.String() {
		values["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["limits"].(map[string]interface{})[util.IntelProvision.String()] = 1
	}
}

// errorAndCleanup returns the given error and deletes resources which might have been created previously
// This prevents secrets and CSRs to stay on the cluster after a failed installation attempt
func errorAndCleanup(err error, kubeClient kubernetes.Interface) error {
	// We dont care about any additional errors here
	cleanupCSR(kubeClient)
	cleanupSecrets(kubeClient)
	return err
}

func debug(format string, v ...interface{}) {
}
