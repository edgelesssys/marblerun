package cmd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
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
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func newInstallCmd() *cobra.Command {
	var settings *cli.EnvSettings
	var domain string
	var chartPath string
	var simulation bool
	var noSgxDevicePlugin bool
	var inject bool
	var meshServerPort int
	var clientServerPort int

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Installs marblerun on a kubernetes cluster",
		Long:  `Installs marblerun on a kubernetes cluster`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			settings = cli.New()
			return cliInstall(chartPath, domain, simulation, noSgxDevicePlugin, inject, clientServerPort, meshServerPort, settings)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&domain, "domain", "localhost", "Sets the CNAME for the coordinator certificate")
	cmd.Flags().StringVar(&chartPath, "marblerun-chart-path", "", "Path to marblerun helm chart")
	cmd.Flags().BoolVar(&simulation, "simulation", false, "Set marblerun to start in simulation mode")
	cmd.Flags().BoolVar(&noSgxDevicePlugin, "no-sgx-device-plugin", false, "Disables the installation of an sgx device plugin")
	cmd.Flags().BoolVar(&inject, "auto-injection", false, "Enable automatic injection of selected namespaces")
	cmd.Flags().IntVar(&meshServerPort, "mesh-server-port", 25554, "Set the mesh server port. Needs to be configured to the same port as in the data-plane marbles")
	cmd.Flags().IntVar(&clientServerPort, "client-server-port", 25555, "Set the client server port. Needs to be configured to the same port as in your client tool stack")

	return cmd
}

// cliInstall installs marblerun on the cluster
func cliInstall(path string, hostname string, sim bool, noSgx bool, inject bool, clientPort int, meshPort int, settings *cli.EnvSettings) error {
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

	if inject {
		if err := installWebhook(vals); err != nil {
			return err
		}
	}

	// create helm installer
	installer := action.NewInstall(actionConfig)
	installer.CreateNamespace = true
	installer.Namespace = "marblerun"
	installer.ReleaseName = "marblerun-coordinator"

	if path == "" {
		// No chart was specified -> look for edgeless repository, if not present add it
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
func getRepo(name string, url string, settings *cli.EnvSettings) error {
	repoFile := settings.RepositoryConfig

	// Ensure the file directory exists as it is required for file locking
	err := os.MkdirAll(filepath.Dir(repoFile), os.ModePerm)
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

	c := repo.Entry{
		Name: name,
		URL:  url,
	}

	if f.Has(name) {
		// Repository is already present on the systems, return nothing
		return nil
	}
	fmt.Printf("Did not find marblerun helm repository on system, adding now...\n")

	r, err := repo.NewChartRepository(&c, getter.All(settings))
	if err != nil {
		return err
	}

	if _, err := r.DownloadIndexFile(); err != nil {
		return errors.New("Chart repository cannot be reached")
	}

	f.Update(&c)

	if err := f.WriteFile(repoFile, 0644); err != nil {
		return err
	}
	fmt.Printf("%s has been added to your helm repositories\n", name)
	return nil
}

// installWebhook enables a mutating admission webhook to allow automatic injection of values into pods
func installWebhook(vals map[string]interface{}) error {
	path, err := findKubeConfig()
	if err != nil {
		return err
	}

	caBundle, err := loadCABundle(path)
	if err != nil {
		return err
	}

	vals["webhook"] = map[string]interface{}{
		"start":    true,
		"CABundle": caBundle,
	}

	return genWebhookCerts()
}

// loadCABundle generates the base64 CA_Bundle string for the k8s webhook configuration
func loadCABundle(path string) (string, error) {
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return "", err
	}
	certRaw, err := ioutil.ReadFile(kubeConfig.CAFile)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(certRaw), nil
}

// get kubernetes config from env variable or "~/.kube/config"
func findKubeConfig() (string, error) {
	path := os.Getenv("KUBECONFIG")
	if path == "" {
		homedir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = homedir + "/.kube/config"
	}
	return path, nil
}

// genWebhookCerts creates a certificate signing request which is signed by the kubernetes API server
// the resulting certificate and used private key are then saved as secrets so they can be used by the
// mutating admission webhook server
func genWebhookCerts() error {
	fmt.Printf("Setting up Marblerun Webhook")

	path, err := findKubeConfig()
	if err != nil {
		return err
	}

	kubeConfig, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return err
	}

	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("failed setting up kubernetes client: %v", err)
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048) // different key size maybe??
	if err != nil {
		return fmt.Errorf("failed creating rsa private key: %v", err)
	}

	fmt.Printf(".")

	csr, err := genCsr(privKey)
	if err != nil {
		return err
	}

	fmt.Printf(".")

	if err := sendAndApprove(csr, kubeClient); err != nil {
		return err
	}

	fmt.Printf(".")

	// get the csr which should now contain the signed certificate
	csr, err = kubeClient.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), "marble-injector.marblerun", metav1.GetOptions{})
	if err != nil {
		return err
	}
	if err := createSecret(privKey, csr.Status.Certificate, kubeClient); err != nil {
		return err
	}

	fmt.Printf(" Done\n")

	return nil
}

// genCsr generates the x509 certificate request
func genCsr(privKey *rsa.PrivateKey) (*certv1.CertificateSigningRequest, error) {
	subj := pkix.Name{
		// we could set more information here, is that needed?
		CommonName:   "system:node:marble-injector.marblerun.svc",
		Organization: []string{"system:nodes"},
	}

	// set KeyUsage extensions. See RFC 5280, Section 4.2.1.3 and Section 4.2.1.12
	extendedUsage := pkix.Extension{
		// id-kp (Extended Key Usage) object identifier
		Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
		Critical: true,
		// id-kp-serverAuth object identifier
		Value: []byte{0x30, 0xa, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x3, 0x1},
	}
	keyUsage := pkix.Extension{
		// id-ce-keyUsage object identifier
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15},
		Critical: true,
		// bit string for key encipherment, digital signature
		Value: []byte{0x3, 0x2, 0x5, 0xa0},
	}

	// create a x509 certificate request
	template := &x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Extensions:         []pkix.Extension{extendedUsage, keyUsage},
		DNSNames:           []string{"marble-injector.marblerun.svc"},
	}

	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, err
	}

	csrPEM := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrRaw,
	}

	// create the k8s certificate request which bundles the x509 csr
	certificateRequest := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "marble-injector.marblerun",
		},
		Spec: certv1.CertificateSigningRequestSpec{
			Request:    pem.EncodeToMemory(csrPEM),
			SignerName: "kubernetes.io/kubelet-serving",
			// usages have to match usages defined in the x509 csr
			Usages: []certv1.KeyUsage{
				"key encipherment", "digital signature", "server auth",
			},
		},
	}
	return certificateRequest, nil
}

// sendAndApprove sends a CertificateSigningRequest and approves it after creation
func sendAndApprove(csr *certv1.CertificateSigningRequest, kubeClient *kubernetes.Clientset) error {
	// send the csr to the k8s api server for signing
	certReturn, err := kubeClient.CertificatesV1().CertificateSigningRequests().Create(context.TODO(), csr, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	if err := waitForResource("marble-injector.marblerun", kubeClient, 10, func(string, *kubernetes.Clientset) bool {
		_, err := kubeClient.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), "marble-injector.marblerun", metav1.GetOptions{})
		if err != nil {
			return false
		}
		return true
	}); err != nil {
		return err
	}

	// approve of the signing, the user performing the install has to be allowed to approv certificates
	// e.g. if he can use kubectl certificate approve $csr_name, then this should also work
	certReturn.Status.Conditions = append(certReturn.Status.Conditions, certv1.CertificateSigningRequestCondition{
		Type:           certv1.RequestConditionType(string(certv1.CertificateApproved)),
		Status:         corev1.ConditionTrue,
		Reason:         "MarblerunInstall",
		Message:        "This CSR was automatically approved after creation with marblerun install.",
		LastUpdateTime: metav1.Now(),
	})

	_, err = kubeClient.CertificatesV1().CertificateSigningRequests().UpdateApproval(context.TODO(), "marble-injector.marblerun", certReturn, metav1.UpdateOptions{})

	return waitForResource("marble-injector.marblerun", kubeClient, 10, func(string, *kubernetes.Clientset) bool {
		csr, err := kubeClient.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), "marble-injector.marblerun", metav1.GetOptions{})
		if err != nil {
			return false
		}
		if len(csr.Status.Certificate) <= 0 {
			return false
		}
		return true
	})
}

// createSecret creates a secret containing the signed certificate and private key for the webhook server
func createSecret(privKey *rsa.PrivateKey, crt []byte, kubeClient *kubernetes.Clientset) error {
	rsaPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		},
	)

	// to create the secret we first have to make sure the namespace exists
	if err := verifyNamespace("marblerun", kubeClient); err != nil {
		return err
	}

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

func verifyNamespace(namespace string, kubeClient *kubernetes.Clientset) error {
	_, err := kubeClient.CoreV1().Namespaces().Get(context.TODO(), "marblerun", metav1.GetOptions{})
	if err != nil {
		// if the namespace does not exist we create it
		if err.Error() == "namespaces \"marblerun\" not found" {
			marbleNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "marblerun",
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

// calls to the CertificateSigningRequests interface are non blocking, we use this function
// to check if a resource has been created and can be used
func waitForResource(name string, kubeClient *kubernetes.Clientset, timeout int, resourceCheck func(string, *kubernetes.Clientset) bool) error {
	for i := 0; i < timeout; i++ {
		if ok := resourceCheck(name, kubeClient); ok == true {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("certificate signing request was not updated after %d attempts. Giving up", timeout)
}

func debug(format string, v ...interface{}) {
}
