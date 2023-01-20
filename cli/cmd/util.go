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
	helmChartNameEnterprise   = "edgeless/marblerun-enterprise"
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

func fetchLatestCoordinatorConfiguration(out io.Writer) error {
	coordinatorVersion, err := getCoordinatorVersion()
	eraURL := fmt.Sprintf("https://github.com/edgelesssys/marblerun/releases/download/%s/coordinator-era.json", coordinatorVersion)
	if err != nil {
		// if errors were caused by an empty kube config file or by being unable to connect to a cluster we assume the Coordinator is running as a standalone
		// and we default to the latest era-config file
		var dnsError *net.DNSError
		if !clientcmd.IsEmptyConfig(err) && !errors.As(err, &dnsError) && !os.IsNotExist(err) {
			return err
		}
		eraURL = "https://github.com/edgelesssys/marblerun/releases/latest/download/coordinator-era.json"
	}

	fmt.Fprintf(out, "No era config file specified, getting config from %s\n", eraURL)
	resp, err := http.Get(eraURL)
	if err != nil {
		return fmt.Errorf("downloading era config for version %s: %w", coordinatorVersion, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading era config for version: %s: %d: %s", coordinatorVersion, resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	era, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("downloading era config for version %s: %w", coordinatorVersion, err)
	}

	if err := os.WriteFile(eraDefaultConfig, era, 0o644); err != nil {
		return fmt.Errorf("writing era config file: %w", err)
	}

	fmt.Fprintf(out, "Got era config for version %s\n", coordinatorVersion)
	return nil
}

// verify the connection to the MarbleRun Coordinator.
func verifyCoordinator(out io.Writer, host, configFilename string, insecure bool, acceptedTCBStatuses []string) ([]*pem.Block, error) {
	// skip verification if specified
	if insecure {
		fmt.Fprintln(out, "Warning: skipping quote verification")
		return era.InsecureGetCertificate(host)
	}

	if configFilename == "" {
		configFilename = eraDefaultConfig

		// reuse existing config from current working directory if none specified
		// or try to get latest config from github if it does not exist
		if _, err := os.Stat(configFilename); err == nil {
			fmt.Fprintln(out, "Reusing existing config file")
		} else if err := fetchLatestCoordinatorConfiguration(out); err != nil {
			return nil, err
		}
	}

	pemBlock, tcbStatus, err := era.GetCertificate(host, configFilename)
	if errors.Is(err, attestation.ErrTCBLevelInvalid) && util.StringSliceContains(acceptedTCBStatuses, tcbStatus.String()) {
		fmt.Fprintln(out, "Warning: TCB level invalid, but accepted by configuration")
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
		return nil, fmt.Errorf("failed setting up kubernetes client: %w", err)
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
