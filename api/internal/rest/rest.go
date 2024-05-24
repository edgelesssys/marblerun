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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/tidwall/gjson"
)

// Endpoints of the MarbleRun Coordinator REST API.
const (
	ManifestEndpoint     = "manifest"
	UpdateEndpoint       = "update"
	UpdateCancelEndpoint = "update-cancel"
	UpdateStatusEndpoint = "update-manifest"
	QuoteEndpoint        = "quote"
	RecoverEndpoint      = "recover"
	SecretEndpoint       = "secrets"
	StatusEndpoint       = "status"
	SignQuoteEndpoint    = "sign-quote"
	V2API                = "/api/v2/"
	ContentJSON          = "application/json"
	ContentPlain         = "text/plain"
)

const (
	eraDefaultConfig = "era-config.json"
	messageField     = "message"
	dataField        = "data"
)

// NotAllowedError is returned when a request receives a 405 Method Not Allowed response.
type NotAllowedError struct {
	method string
	url    string
}

// NewNotAllowedError creates a new NotAllowedError.
func NewNotAllowedError(method, url string) error {
	return &NotAllowedError{method: method, url: url}
}

// Error returns the error message.
func (e *NotAllowedError) Error() string {
	return fmt.Sprintf("%s %s: method not allowed", e.method, e.url)
}

// Client is a REST client for the MarbleRun Coordinator.
type Client struct {
	client *http.Client
	host   string
}

// NewClient creates and returns an http client using the given certificate of the server.
// An optional clientCert can be used to enable client authentication.
func NewClient(host string, rootCert *x509.Certificate, clientCert *tls.Certificate) (*Client, error) {
	tlsConfig := &tls.Config{
		RootCAs: x509.NewCertPool(),
	}
	if clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*clientCert}
	}
	if rootCert == nil {
		tlsConfig.InsecureSkipVerify = true
	} else {
		tlsConfig.RootCAs.AddCert(rootCert)
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
	case http.StatusMethodNotAllowed:
		return nil, NewNotAllowedError(req.Method, req.URL.String())
	default:
		return nil, fmt.Errorf("%s %s: %s %s", req.Method, req.URL.String(), resp.Status, msg)
	}
}
