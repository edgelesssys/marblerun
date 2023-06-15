// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package rest provides methods and functions to communicate
// with the MarbleRun Coordinator using its REST API.
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

// Endpoints of the MarbleRun Coordinator REST API.
const (
	ManifestEndpoint     = "manifest"
	UpdateEndpoint       = "update"
	UpdateCancelEndpoint = "update-cancel"
	UpdateStatusEndpoint = "update-manifest"
	RecoverEndpoint      = "recover"
	SecretEndpoint       = "secrets"
	StatusEndpoint       = "status"
	ContentJSON          = "application/json"
	ContentPlain         = "text/plain"
)

const (
	eraDefaultConfig = "era-config.json"
	messageField     = "message"
	dataField        = "data"
)

// Flags are command line flags used to configure the REST client.
type Flags struct {
	EraConfig           string
	Insecure            bool
	AcceptedTCBStatuses []string
}

// ParseFlags parses the command line flags used to configure the REST client.
func ParseFlags(cmd *cobra.Command) (Flags, error) {
	eraConfig, err := cmd.Flags().GetString("era-config")
	if err != nil {
		return Flags{}, err
	}
	insecure, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		return Flags{}, err
	}
	acceptedTCBStatuses, err := cmd.Flags().GetStringSlice("accepted-tcb-statuses")
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

// Client is a REST client for the MarbleRun Coordinator.
type Client struct {
	client *http.Client
	host   string
}

// NewClient creates and returns an http client using the flags of cmd.
func NewClient(cmd *cobra.Command, host string) (*Client, error) {
	flags, err := ParseFlags(cmd)
	if err != nil {
		return nil, fmt.Errorf("parsing flags: %w", err)
	}
	caCert, err := VerifyCoordinator(
		cmd.Context(), cmd.OutOrStdout(), host,
		flags.EraConfig, flags.Insecure, flags.AcceptedTCBStatuses,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to verify Coordinator enclave: %w", err)
	}
	return newClient(host, caCert, nil)
}

// NewAuthenticatedClient creates and returns an http client with client authentication using the flags of cmd.
func NewAuthenticatedClient(cmd *cobra.Command, host string) (*Client, error) {
	flags, err := parseAuthenticatedFlags(cmd)
	if err != nil {
		return nil, fmt.Errorf("parsing flags: %w", err)
	}
	caCert, err := VerifyCoordinator(
		cmd.Context(), cmd.OutOrStdout(), host,
		flags.EraConfig, flags.Insecure, flags.AcceptedTCBStatuses,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to verify Coordinator enclave: %w", err)
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
// If body is non nil, it is sent as the request body.
// Query parameters can be provided as a list of strings, where each pair of strings is a key-value pair.
// On success, the data field of the JSON response is returned.
func (c *Client) Get(ctx context.Context, path string, body io.Reader, queryParameters ...string) ([]byte, error) {
	if len(queryParameters)%2 != 0 {
		return nil, errors.New("query parameters must be provided in pairs")
	}
	query := url.Values{}
	for i := 0; i < len(queryParameters); i += 2 {
		query.Add(queryParameters[i], queryParameters[i+1])
	}

	uri := url.URL{Scheme: "https", Host: c.host, Path: path, RawQuery: query.Encode()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), body)
	if err != nil {
		return nil, err
	}

	return c.do(req)
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

	return c.do(req)
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	msg := gjson.GetBytes(respBody, messageField).String()

	switch resp.StatusCode {
	case http.StatusOK:
		// return data field of JSON response
		data := gjson.GetBytes(respBody, dataField).String()
		return []byte(data), nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("%s %s: authorizing user: %s", req.Method, req.URL.String(), msg)
	default:
		return nil, fmt.Errorf("%s %s: %s %s", req.Method, req.URL.String(), resp.Status, msg)
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
	if !errors.Is(err, attestation.ErrTCBLevelInvalid) {
		return pemBlock, err
	}
	if !util.StringSliceContains(acceptedTCBStatuses, tcbStatus.String()) {
		return nil, fmt.Errorf("TCB level invalid: %v", tcbStatus)
	}
	fmt.Fprintln(out, "Warning: TCB level invalid, but accepted by configuration:", tcbStatus)
	return pemBlock, nil
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, eraURL, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
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
