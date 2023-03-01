// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package rest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/era/era"
	"github.com/edgelesssys/era/util"
	"github.com/edgelesssys/marblerun/cli/internal/kube"
	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
	"k8s.io/client-go/tools/clientcmd"
)

const eraDefaultConfig = "era-config.json"

// Flags are command line flags used to configure the REST client.
type Flags struct {
	EraConfig           string
	Insecure            bool
	AcceptedTCBStatuses []string
}

func ParseFlags(cmd *cobra.Command) (Flags, error) {
	eraConfig, err := cmd.Flags().GetString("era-config")
	if err != nil {
		return Flags{}, err
	}
	insecure, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		return Flags{}, err
	}
	acceptedTCBStatuses, err := cmd.Flags().GetStringArray("accepted-tcb-statuses")
	if err != nil {
		return Flags{}, err
	}

	return Flags{
		EraConfig:           eraConfig,
		Insecure:            insecure,
		AcceptedTCBStatuses: acceptedTCBStatuses,
	}, nil
}

type authenticatedFlags struct {
	Flags
	ClientCert tls.Certificate
}

func parseAuthenticatedFlags(cmd *cobra.Command) (authenticatedFlags, error) {
	flags, err := ParseFlags(cmd)
	if err != nil {
		return authenticatedFlags{}, err
	}
	certFile, err := cmd.Flags().GetString("cert")
	if err != nil {
		return authenticatedFlags{}, err
	}
	keyFile, err := cmd.Flags().GetString("key")
	if err != nil {
		return authenticatedFlags{}, err
	}
	clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return authenticatedFlags{}, err
	}

	return authenticatedFlags{
		Flags:      flags,
		ClientCert: clientCert,
	}, nil
}

type Client struct {
	client *http.Client
	host   string
}

// NewClient creates and returns an http client using the flags of cmd.
func NewClient(cmd *cobra.Command, host string) (*Client, error) {
	flags, err := ParseFlags(cmd)
	if err != nil {
		return nil, err
	}
	caCert, err := VerifyCoordinator(
		cmd.Context(), cmd.OutOrStdout(), host,
		flags.EraConfig, flags.Insecure, flags.AcceptedTCBStatuses,
	)
	if err != nil {
		return nil, err
	}
	return newClient(host, caCert, nil)
}

// NewAuthenticatedClient creates and returns an http client with client authentication using the flags of cmd.
func NewAuthenticatedClient(cmd *cobra.Command, host string) (*Client, error) {
	flags, err := parseAuthenticatedFlags(cmd)
	if err != nil {
		return nil, err
	}
	caCert, err := VerifyCoordinator(
		cmd.Context(), cmd.OutOrStdout(), host,
		flags.EraConfig, flags.Insecure, flags.AcceptedTCBStatuses,
	)
	if err != nil {
		return nil, err
	}
	return newClient(host, caCert, &flags.ClientCert)
}

func newClient(host string, caCert []*pem.Block, clCert *tls.Certificate) (*Client, error) {
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
	return &Client{
		client: client,
		host:   host,
	}, nil
}

// Get sends a GET request to the Coordinator under the specified path.
// Optionally, a body can be provided.
func (c *Client) Get(ctx context.Context, path string, body io.Reader) ([]byte, error) {
	uri := url.URL{Scheme: "https", Host: c.host, Path: path}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), body)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	msg := gjson.GetBytes(respBody, "message").String()

	switch resp.StatusCode {
	case http.StatusOK:
		return respBody, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("GET %s: unable to authorize user: %s", uri.String(), msg)
	default:
		return nil, fmt.Errorf("GET %s: %d %s: %s", uri.String(), resp.StatusCode, http.StatusText(resp.StatusCode), msg)
	}
}

// Post sends a POST request to the Coordinator under the specified path.
// Optionally, a body can be provided.
func (c *Client) Post(ctx context.Context, path, contentType string, body io.Reader) ([]byte, error) {
	uri := url.URL{Scheme: "https", Host: c.host, Path: path}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri.String(), body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	msg := gjson.GetBytes(respBody, "message").String()

	switch resp.StatusCode {
	case http.StatusOK:
		return respBody, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("POST %s: unable to authorize user: %s", uri.String(), msg)
	default:
		return nil, fmt.Errorf("POST %s: %d %s: %s", uri.String(), resp.StatusCode, http.StatusText(resp.StatusCode), msg)
	}
}

// VerifyCoordinator verifies the connection to the MarbleRun Coordinator.
func VerifyCoordinator(
	ctx context.Context, out io.Writer, host, configFilename string,
	insecure bool, acceptedTCBStatuses []string,
) ([]*pem.Block, error) {
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
		} else if err := fetchLatestCoordinatorConfiguration(ctx, out); err != nil {
			return nil, err
		}
	}

	pemBlock, tcbStatus, err := era.GetCertificate(host, configFilename)
	if errors.Is(err, attestation.ErrTCBLevelInvalid) &&
		util.StringSliceContains(acceptedTCBStatuses, tcbStatus.String()) {
		fmt.Fprintln(out, "Warning: TCB level invalid, but accepted by configuration")
		return pemBlock, nil
	}
	return pemBlock, err
}

func fetchLatestCoordinatorConfiguration(ctx context.Context, out io.Writer) error {
	coordinatorVersion, err := kube.CoordinatorVersion(ctx)
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
