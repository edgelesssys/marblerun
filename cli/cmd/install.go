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

	"github.com/gofrs/flock"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func newInstallCmd() *cobra.Command {
	var settings *cli.EnvSettings
	var domain string
	var chartPath string
	var chartVersion string
	var simulation bool
	var noSgxDevicePlugin bool
	var disableInjection bool
	var meshServerPort int
	var clientServerPort int

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Installs marblerun on a kubernetes cluster",
		Long:  `Installs marblerun on a kubernetes cluster`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			settings = cli.New()
			return cliInstall(chartPath, domain, chartVersion, simulation, noSgxDevicePlugin, disableInjection, clientServerPort, meshServerPort, settings)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&domain, "domain", "localhost", "Sets the CNAME for the coordinator certificate")
	cmd.Flags().StringVar(&chartPath, "marblerun-chart-path", "", "Path to marblerun helm chart")
	cmd.Flags().StringVar(&chartVersion, "version", "", "Version of the Coordinator to install, latest by default")
	cmd.Flags().BoolVar(&simulation, "simulation", false, "Set marblerun to start in simulation mode")
	cmd.Flags().BoolVar(&noSgxDevicePlugin, "no-sgx-device-plugin", false, "Disables the installation of an sgx device plugin")
	cmd.Flags().BoolVar(&disableInjection, "disable-auto-injection", false, "Disable automatic injection of selected namespaces")
	cmd.Flags().IntVar(&meshServerPort, "mesh-server-port", 2001, "Set the mesh server port. Needs to be configured to the same port as in the data-plane marbles")
	cmd.Flags().IntVar(&clientServerPort, "client-server-port", 4433, "Set the client server port. Needs to be configured to the same port as in your client tool stack")

	return cmd
}

// cliInstall installs marblerun on the cluster
func cliInstall(path string, hostname string, version string, sim bool, noSgx bool, disableInjection bool, clientPort int, meshPort int, settings *cli.EnvSettings) error {
	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(settings.RESTClientGetter(), "marblerun", os.Getenv("HELM_DRIVER"), debug); err != nil {
		return err
	}

	// set overwrite values
	var vals map[string]interface{}
	if sim {
		// simulation mode, disable tolerations and resources, set simulation to 1
		vals = map[string]interface{}{
			"tolerations": nil,
			"coordinator": map[string]interface{}{
				"simulation": "1",
				"resources":  nil,
				"hostname":   hostname,
			},
		}
	} else {
		vals = map[string]interface{}{
			"coordinator": map[string]interface{}{
				"hostname": hostname,
			},
		}
	}
	if noSgx {
		// disable deployment of sgx-device-plugin pod
		vals["coordinator"].(map[string]interface{})["resources"] = nil
		vals["sgxDevice"] = map[string]interface{}{
			"start": false,
		}
	}
	vals["coordinator"].(map[string]interface{})["meshServerPort"] = meshPort
	vals["coordinator"].(map[string]interface{})["clientServerPort"] = clientPort

	if !disableInjection {
		if err := installWebhook(vals); err != nil {
			return err
		}
	}

	// create helm installer
	installer := action.NewInstall(actionConfig)
	installer.CreateNamespace = true
	installer.Namespace = "marblerun"
	installer.ReleaseName = "marblerun-coordinator"
	installer.ChartPathOptions.Version = version

	if path == "" {
		// No chart was specified -> add or update edgeless helm repo
		err := getRepo("edgeless", "https://helm.edgeless.systems/stable", settings)
		if err != nil {
			return err
		}
		path, err = installer.ChartPathOptions.LocateChart("edgeless/marblerun-coordinator", settings)
		if err != nil {
			return err
		}
	}
	chart, err := loader.Load(path)
	if err != nil {
		return err
	}

	if err := chartutil.ValidateAgainstSchema(chart, vals); err != nil {
		return err
	}

	if _, err := installer.Run(chart, vals); err != nil {
		return err
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
		return errors.New("Chart repository cannot be reached")
	}

	f.Update(c)

	if err := f.WriteFile(repoFile, 0644); err != nil {
		return err
	}
	return nil
}

// installWebhook enables a mutating admission webhook to allow automatic injection of values into pods
func installWebhook(vals map[string]interface{}) error {
	kubeClient, err := getKubernetesInterface()
	if err != nil {
		return err
	}

	// verify marblerun namespace exists, if not create it
	if err := verifyNamespace("marblerun", kubeClient); err != nil {
		return err
	}

	fmt.Printf("Setting up Marblerun Webhook")
	certificateHandler, err := getCertificateHandler(kubeClient)
	if err != nil {
		return err
	}
	fmt.Printf(".")
	err = certificateHandler.signRequest()
	if err != nil {
		return err
	}
	fmt.Printf(".")
	certificateHandler.setCaBundle(vals)
	cert, err := certificateHandler.get()
	if err != nil {
		return err
	}
	if len(cert) <= 0 {
		return fmt.Errorf("certificate was not signed by the CA")
	}
	fmt.Printf(".")

	if err := createSecret(certificateHandler.getKey(), cert, kubeClient); err != nil {
		return err
	}
	fmt.Printf(" Done\n")
	return nil
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

func debug(format string, v ...interface{}) {
}
