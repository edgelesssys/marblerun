// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/era/era"
	"github.com/edgelesssys/era/util"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const webhookName = "marble-injector.marblerun"

// helm constants.
const (
	helmChartName             = "edgeless/marblerun"
	helmCoordinatorDeployment = "marblerun-coordinator"
	helmInjectorDeployment    = "marble-injector"
	helmNamespace             = "marblerun"
	helmRelease               = "marblerun"
	helmRepoURI               = "https://helm.edgeless.systems/stable"
	helmRepoName              = "edgeless"
)

const promptForChanges = "Do you want to automatically apply the suggested changes [y/n]? "

const eraDefaultConfig = "era-config.json"

var (
	eraConfig           string
	insecureEra         bool
	acceptedTCBStatuses []string
)

func fetchLatestCoordinatorConfiguration() error {
	coordinatorVersion, err := getCoordinatorVersion()
	eraURL := fmt.Sprintf("https://github.com/edgelesssys/marblerun/releases/download/%s/coordinator-era.json", coordinatorVersion)
	if err != nil {
		// if errors were caused by an empty kube config file or by being unable to connect to a cluster we assume the Coordinator is running as a standlone
		// and we default to the latest era-config file
		var dnsError *net.DNSError
		if !clientcmd.IsEmptyConfig(err) && !errors.As(err, &dnsError) && !os.IsNotExist(err) {
			return err
		}
		eraURL = "https://github.com/edgelesssys/marblerun/releases/latest/download/coordinator-era.json"
	}

	fmt.Printf("No era config file specified, getting config from %s\n", eraURL)
	resp, err := http.Get(eraURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading era config failed with error %d: %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	out, err := os.Create(eraDefaultConfig)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	fmt.Println("Got latest config")
	return nil
}

// verify the connection to the MarbleRun Coordinator.
func verifyCoordinator(host string, configFilename string, insecure bool, acceptedTCBStatuses []string) ([]*pem.Block, error) {
	// skip verification if specified
	if insecure {
		fmt.Println("Warning: skipping quote verification")
		return era.InsecureGetCertificate(host)
	}

	var configFile string
	// get certificate using provided config
	if configFilename != "" {
		configFile = configFilename
	} else {
		// get latest config from github if none specified
		if err := fetchLatestCoordinatorConfiguration(); err != nil {
			return nil, err
		}
		configFile = eraDefaultConfig
	}

	pemBlock, tcbStatus, err := era.GetCertificate(host, configFile)
	if errors.Is(err, attestation.ErrTCBLevelInvalid) && util.StringSliceContains(acceptedTCBStatuses, tcbStatus.String()) {
		fmt.Println("Warning: TCB level invalid, but accepted by configuration")
		return pemBlock, nil
	}
	return pemBlock, err
}

// restClient creates and returns a http client using a provided root certificate and optional client certificate to communicate with the Coordinator REST API.
func restClient(caCert []*pem.Block, clCert *tls.Certificate) (*http.Client, error) {
	// Set rootCA for connection to Coordinator
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(pem.EncodeToMemory(caCert[len(caCert)-1])); !ok {
		return nil, errors.New("failed to parse certificate")
	}
	// Add intermediate cert if applicable
	if len(caCert) > 1 {
		if ok := certPool.AppendCertsFromPEM(pem.EncodeToMemory(caCert[0])); !ok {
			return nil, errors.New("failed to parse certificate")
		}
	}

	var tlsConfig *tls.Config
	if clCert != nil {
		tlsConfig = &tls.Config{
			RootCAs:      certPool,
			Certificates: []tls.Certificate{*clCert},
		}
	} else {
		tlsConfig = &tls.Config{
			RootCAs: certPool,
		}
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	return client, nil
}

// getKubernetesInterface returns the kubernetes Clientset to interact with the k8s API.
func getKubernetesInterface() (*kubernetes.Clientset, error) {
	path := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	if path == "" {
		homedir, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(homedir, clientcmd.RecommendedHomeDir, clientcmd.RecommendedFileName)
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

func promptYesNo(stdin io.Reader, question string) (bool, error) {
	fmt.Print(question)
	reader := bufio.NewReader(stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	response = strings.ToLower(strings.TrimSpace(response))

	if response != "y" && response != "yes" {
		return false, nil
	}

	return true, nil
}

func checkLegacyKubernetesVersion(kubeClient kubernetes.Interface) (bool, error) {
	serverVersion, err := kubeClient.Discovery().ServerVersion()
	if err != nil {
		return false, err
	}
	versionInfo, err := version.ParseGeneric(serverVersion.String())
	if err != nil {
		return false, err
	}

	// return the legacy if kubernetes version is < 1.19
	if versionInfo.Major() == 1 && versionInfo.Minor() < 19 {
		return true, nil
	}

	return false, nil
}
