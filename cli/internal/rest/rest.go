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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/edgelesssys/marblerun/cli/internal/kube"
	"github.com/edgelesssys/marblerun/internal/attestation"
	"github.com/edgelesssys/marblerun/internal/tcb"
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

// VerifyCoordinatorOptions defines the options for verifying the connection to the MarbleRun Coordinator.
type VerifyCoordinatorOptions struct {
	// ConfigFilename is the path to the era config file.
	ConfigFilename string
	// K8sNamespace is the namespace of the MarbleRun installation.
	// We use this to try to find the Coordinator when retrieving the era config.
	K8sNamespace string
	// Insecure is a flag to disable TLS verification.
	Insecure bool
	// AcceptedTCBStatuses is a list of TCB statuses that are accepted by the CLI.
	// This can be used to allow connections to Coordinator instances running on outdated hardware or firmware.
	AcceptedTCBStatuses []string
	// Nonce is a user supplied nonce to be used in the attestation process.
	Nonce []byte
	// SGXQuotePath is the path to save SGX quote file.
	SGXQuotePath string
}

// Client is a REST client for the MarbleRun Coordinator.
type Client struct {
	client *http.Client
	host   string
}

// NewClient creates and returns an http client using the given certificate of the server.
// An optional clientCert can be used to enable client authentication.
func NewClient(host string, caCert []*pem.Block, clientCert *tls.Certificate, insecureTLS bool) (*Client, error) {
	// Set rootCA for connection to Coordinator
	certPool := x509.NewCertPool()

	if len(caCert) == 0 && !insecureTLS {
		return nil, errors.New("no certificates provided")
	} else if !insecureTLS {
		if ok := certPool.AppendCertsFromPEM(pem.EncodeToMemory(caCert[len(caCert)-1])); !ok {
			return nil, errors.New("failed to parse certificate")
		}
	}

	var tlsConfig *tls.Config
	if clientCert != nil {
		tlsConfig = &tls.Config{
			RootCAs:            certPool,
			Certificates:       []tls.Certificate{*clientCert},
			InsecureSkipVerify: insecureTLS,
		}
	} else {
		tlsConfig = &tls.Config{
			RootCAs:            certPool,
			InsecureSkipVerify: insecureTLS,
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
func VerifyCoordinator(ctx context.Context, out io.Writer, host string, opts VerifyCoordinatorOptions) ([]*pem.Block, error) {
	// skip verification if specified
	if opts.Insecure {
		fmt.Fprintln(out, "Warning: skipping quote verification")
		certs, _, err := attestation.InsecureGetCertificate(ctx, host)
		return certs, err
	}

	if opts.ConfigFilename == "" {
		opts.ConfigFilename = eraDefaultConfig

		// reuse existing config from current working directory if none specified
		// or try to get latest config from github if it does not exist
		if _, err := os.Stat(opts.ConfigFilename); err == nil {
			fmt.Fprintln(out, "Reusing existing config file")
		} else if err := fetchLatestCoordinatorConfiguration(ctx, out, opts.K8sNamespace); err != nil {
			return nil, err
		}
	}

	eraCfgRaw, err := os.ReadFile(opts.ConfigFilename)
	if err != nil {
		return nil, fmt.Errorf("reading era config file: %w", err)
	}

	var eraCfg attestation.Config
	if err := json.Unmarshal(eraCfgRaw, &eraCfg); err != nil {
		return nil, fmt.Errorf("unmarshalling era config: %w", err)
	}

	pemBlock, tcbStatus, rawQuote, err := attestation.GetCertificate(ctx, host, opts.Nonce, eraCfg)
	validity, err := tcb.CheckStatus(tcbStatus, err, opts.AcceptedTCBStatuses)
	if err != nil {
		return nil, err
	}
	switch validity {
	case tcb.ValidityUnconditional:
	case tcb.ValidityConditional:
		fmt.Fprintln(out, "TCB level accepted by configuration:", tcbStatus)
	default:
		fmt.Fprintln(out, "Warning: TCB level invalid, but accepted by configuration:", tcbStatus)
	}

	if opts.SGXQuotePath != "" {
		if err := os.WriteFile(opts.SGXQuotePath, rawQuote, 0o644); err != nil {
			return nil, fmt.Errorf("saving SGX quote to disk: %w", err)
		}
	}

	return pemBlock, nil
}

func fetchLatestCoordinatorConfiguration(ctx context.Context, out io.Writer, k8sNamespace string) error {
	coordinatorVersion, err := kube.CoordinatorVersion(ctx, k8sNamespace)
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

	if coordinatorVersion != "" {
		fmt.Fprintf(out, "Got era config for version %s\n", coordinatorVersion)
	} else {
		fmt.Fprintln(out, "Got latest era config")
	}
	return nil
}
