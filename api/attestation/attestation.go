// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package attestation

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/edgelesssys/marblerun/internal/tcb"
)

// TCBStatusError is returned when the TCB status of a Coordinator enclave is not accepted by a given configuration.
type TCBStatusError struct {
	// TCBStatus is the TCB status of the Coordinator enclave.
	TCBStatus tcbstatus.Status
	// Advisories is a list of Intel Security Advisories if the TCB status is SWHardeningNeeded.
	Advisories []string
}

// NewTCBStatusError creates a new TCBStatusError.
func NewTCBStatusError(tcbStatus tcbstatus.Status) error {
	return &TCBStatusError{TCBStatus: tcbStatus}
}

// NewTCBStatusErrorWithAdvisories creates a new TCBStatusError with a list of Intel Security Advisories.
func NewTCBStatusErrorWithAdvisories(tcbStatus tcbstatus.Status, advisories []string) error {
	return &TCBStatusError{TCBStatus: tcbStatus, Advisories: advisories}
}

// Error returns the error message.
func (e *TCBStatusError) Error() string {
	var advisoryMsg string
	if len(e.Advisories) > 0 {
		advisoryMsg = fmt.Sprintf(": advisories not accepted by configuration: %s", e.Advisories)
	}
	return fmt.Sprintf("invalid TCB status: %s%s", e.TCBStatus, advisoryMsg)
}

// Config is the expected attestation metadata of a MarbleRun Coordinator enclave.
// It is used to verify the Coordinator's remote attestation report.
// At minimum, either UniqueID or the tuple of SignerID, ProductID, and SecurityVersion must be provided.
type Config struct {
	SecurityVersion     uint
	UniqueID            string
	SignerID            string
	ProductID           uint16
	Debug               bool
	Nonce               []byte
	AcceptedTCBStatuses []string
	AcceptedAdvisories  []string
}

// VerifyCertificate verifies the Coordinator's TLS certificate against the Coordinator's SGX quote.
// A config with the expected attestation metadata must be provided.
func VerifyCertificate(out io.Writer, rootCert *x509.Certificate, quote []byte, config Config) error {
	return verifyCertificate(out, rootCert, quote, config, verifyRemoteReport)
}

func verifyCertificate(
	out io.Writer, rootCert *x509.Certificate, quote []byte, config Config,
	verifyQuote func(quote []byte) (attestation.Report, error),
) error {
	report, quoteErr := verifyQuote(quote)
	if quoteErr != nil && !errors.Is(quoteErr, attestation.ErrTCBLevelInvalid) {
		return quoteErr
	}

	if err := verifyReport(report, rootCert.Raw, config); err != nil {
		return err
	}

	validity, err := tcb.CheckStatus(report.TCBStatus, quoteErr, config.AcceptedTCBStatuses)
	if err != nil {
		return NewTCBStatusError(report.TCBStatus)
	}

	notAccepted, err := tcb.CheckAdvisories(report, config.AcceptedAdvisories)
	if err != nil {
		return err
	}
	if len(notAccepted) > 0 {
		return NewTCBStatusErrorWithAdvisories(report.TCBStatus, notAccepted)
	}

	switch validity {
	case tcb.ValidityUnconditional:
	case tcb.ValidityConditional:
		fmt.Fprintln(out, "TCB level accepted by configuration:", report.TCBStatus)
	default:
		fmt.Fprintln(out, "Warning: TCB level invalid, but accepted by configuration:", report.TCBStatus)
	}

	if validity != tcb.ValidityUnconditional {
		if report.TCBAdvisoriesErr != nil {
			fmt.Fprintln(out, "Error: TCB Advisories:", report.TCBAdvisoriesErr)
		} else {
			fmt.Fprintln(out, "TCB Advisories:", report.TCBAdvisories)
		}
	}

	return nil
}

// verifyReport checks the attestation report against the provided configuration.
// The reports quote must match the hash of the certificate and (optional) nonce.
func verifyReport(report attestation.Report, cert []byte, cfg Config) error {
	hash := sha256.Sum256(append(cert, cfg.Nonce...))
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
