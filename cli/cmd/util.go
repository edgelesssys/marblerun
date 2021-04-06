package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/edgelesssys/era/era"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const webhookName = "marble-injector.marblerun"

var eraConfig string
var insecureEra bool

// verify the connection to the marblerun coordinator
func verifyCoordinator(host string, configFilename string, insecure bool) ([]*pem.Block, error) {
	// skip verification if specified
	if insecure {
		fmt.Println("Warning: skipping quote verification")
		return era.InsecureGetCertificate(host)
	}

	// get certificate using provided config
	if configFilename != "" {
		return era.GetCertificate(host, configFilename)
	}

	// get latest config from github if none specified
	coordinatorVersion, err := getCoordinatorVersion()
	if err != nil {
		return nil, err
	}
	eraURL := fmt.Sprintf("https://github.com/edgelesssys/marblerun/releases/%s/download/coordinator-era.json", coordinatorVersion)

	fmt.Printf("No era config file specified, getting config from %s\n", eraURL)
	resp, err := http.Get(eraURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := os.Create("era-config.json")
	if err != nil {
		return nil, err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return nil, err
	}
	fmt.Println("Got latest config")

	return era.GetCertificate(host, "era-config.json")
}

// restClient creates and returns a http client using a provided certificate to communicate with the Coordinator REST API
func restClient(cert []*pem.Block) (*http.Client, error) {
	// Set rootCA for connection to coordinator
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(pem.EncodeToMemory(cert[len(cert)-1])); !ok {
		return &http.Client{}, fmt.Errorf("failed to parse root certificate")
	}
	// Add intermediate cert if applicable
	if len(cert) > 1 {
		if ok := certPool.AppendCertsFromPEM(pem.EncodeToMemory(cert[0])); !ok {
			return &http.Client{}, fmt.Errorf("failed to parse intermediate certificate")
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}

	return client, nil
}

// getKubernetesInterface returns the kubernetes Clientset to interact with the k8s API
func getKubernetesInterface() (*kubernetes.Clientset, error) {
	path := os.Getenv("KUBECONFIG")
	if path == "" {
		homedir, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(homedir, ".kube", "config")
	}

	kubeConfig, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return nil, err
	}

	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed setting up kubernetes client: %v", err)
	}

	return kubeClient, nil
}
