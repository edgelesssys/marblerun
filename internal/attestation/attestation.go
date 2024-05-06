// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package attestation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/edgelesssys/ego/eclient"
	"github.com/tidwall/gjson"
)

// Config is the expected attestation metadata of a MarbleRun Coordinator enclave.
// It is used to verify the Coordinator's remote attestation report.
// At minimum, either UniqueID or the tuple of SignerID, ProductID, and SecurityVersion must be provided.
type Config struct {
	SecurityVersion uint   `json:"SecurityVersion"`
	UniqueID        string `json:"UniqueID"`
	SignerID        string `json:"SignerID"`
	ProductID       uint16 `json:"ProductID"`
	Debug           bool   `json:"Debug"`
}

// ErrEmptyQuote defines an error type when no quote was received. This likely occurs when the host is running in OE Simulation mode.
var ErrEmptyQuote = errors.New("no quote received")

// GetCertificate gets the Coordinator's TLS certificate using remote attestation.
// A config with the expected attestation metadata must be provided.
// An optional nonce may be provided to force the Coordinator to generate a new quote for this request.
// It returns the verified certificate chain in PEM format, the TCB status of the enclave, the quote, and an error, if any.
func GetCertificate(ctx context.Context, host string, nonce []byte, config Config) ([]*pem.Block, tcbstatus.Status, []byte, error) {
	return getCertificate(ctx, host, nonce, config, eclient.VerifyRemoteReport)
}

// InsecureGetCertificate gets the Coordinator's TLS certificate, but does not perform remote attestation.
func InsecureGetCertificate(ctx context.Context, host string) ([]*pem.Block, []byte, error) {
	certs, _, quote, err := getCertificate(ctx, host, nil, Config{}, nil)
	return certs, quote, err
}

type verifyFunc func([]byte) (attestation.Report, error)

func getCertificate(ctx context.Context, host string, nonce []byte, config Config, verifyRemoteReport verifyFunc) ([]*pem.Block, tcbstatus.Status, []byte, error) {
	cert, quote, err := httpGetCertQuote(ctx, host, nonce)
	if err != nil {
		return nil, tcbstatus.Unknown, nil, err
	}

	var certs []*pem.Block
	block, rest := pem.Decode([]byte(cert))
	if block == nil {
		return nil, tcbstatus.Unknown, nil, errors.New("could not parse certificate")
	}
	certs = append(certs, block)

	// If we get more than one certificate, append it to the slice
	for len(rest) > 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, tcbstatus.Unknown, nil, errors.New("could not parse certificate chain")
		}
		certs = append(certs, block)
	}

	if verifyRemoteReport == nil {
		return certs, tcbstatus.Unknown, quote, nil
	}

	if len(quote) == 0 {
		return nil, tcbstatus.Unknown, quote, ErrEmptyQuote
	}

	report, verifyErr := verifyRemoteReport(quote)
	if verifyErr != nil && verifyErr != attestation.ErrTCBLevelInvalid {
		return nil, tcbstatus.Unknown, quote, verifyErr
	}

	// Use Root CA (last entry in certs) for attestation
	certRaw := certs[len(certs)-1].Bytes

	if err := verifyReport(report, certRaw, nonce, config); err != nil {
		return nil, tcbstatus.Unknown, quote, err
	}

	return certs, report.TCBStatus, quote, verifyErr
}

// verifyReport checks the attestation report against the provided configuration.
// The reports quote must match the hash of the certificate and (optional) nonce.
func verifyReport(report attestation.Report, cert, nonce []byte, cfg Config) error {
	hash := sha256.Sum256(append(cert, nonce...))
	if !bytes.Equal(report.Data[:len(hash)], hash[:]) {
		return errors.New("report data does not match the certificate's hash")
	}

	if cfg.UniqueID == "" {
		if cfg.SecurityVersion == 0 {
			return errors.New("missing SecurityVersion in config")
		}
		if cfg.ProductID == 0 {
			return errors.New("missing ProductID in config")
		}
	}

	if cfg.SecurityVersion != 0 && report.SecurityVersion < cfg.SecurityVersion {
		return errors.New("invalid SecurityVersion")
	}
	if cfg.ProductID != 0 && binary.LittleEndian.Uint16(report.ProductID) != cfg.ProductID {
		return errors.New("invalid ProductID")
	}
	if report.Debug && !cfg.Debug {
		return errors.New("debug enclave not allowed")
	}
	if err := verifyID(cfg.UniqueID, report.UniqueID, "UniqueID"); err != nil {
		return err
	}
	if err := verifyID(cfg.SignerID, report.SignerID, "SignerID"); err != nil {
		return err
	}
	if cfg.UniqueID == "" && cfg.SignerID == "" {
		fmt.Println("Warning: Configuration contains neither UniqueID nor SignerID!")
	}

	return nil
}

func verifyID(expected string, actual []byte, name string) error {
	if expected == "" {
		return nil
	}
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(expectedBytes, actual) {
		return errors.New("invalid " + name)
	}
	return nil
}

// httpGetCertQuote requests the Coordinator's quote and certificate chain.
func httpGetCertQuote(ctx context.Context, host string, nonce []byte) (string, []byte, error) {
	client := http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	path := "quote" // use v1 path for compatibility with old Coordinators if nonce is not provided
	var query string
	if len(nonce) > 0 {
		path = "api/v2/quote"
		query = url.Values{"nonce": []string{base64.URLEncoding.EncodeToString(nonce)}}.Encode()
	}

	url := url.URL{Scheme: "https", Host: host, Path: path, RawQuery: query}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), http.NoBody)
	if err != nil {
		return "", nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}

	if resp.StatusCode != http.StatusOK {
		errorMessage := gjson.GetBytes(body, "message")
		if errorMessage.Exists() {
			return "", nil, errors.New(resp.Status + ": " + errorMessage.String())
		}
		return "", nil, errors.New(resp.Status + ": " + string(body))
	}

	var certQuote certQuoteResp
	if err := json.Unmarshal([]byte(gjson.GetBytes(body, "data").String()), &certQuote); err != nil {
		return "", nil, err
	}
	return certQuote.Cert, certQuote.Quote, nil
}

type certQuoteResp struct {
	Cert  string
	Quote []byte
}
