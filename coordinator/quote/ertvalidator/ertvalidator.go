// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ertvalidator

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/edgelesssys/ego/enclave"
	"github.com/edgelesssys/marblerun/coordinator/quote"
)

// ERTValidator is a Quote validatior based on EdgelessRT.
type ERTValidator struct{}

// NewERTValidator returns a new ERTValidator object.
func NewERTValidator() *ERTValidator {
	return &ERTValidator{}
}

// Validate implements the Validator interface for ERTValidator.
func (m *ERTValidator) Validate(givenQuote []byte, cert []byte, pp quote.PackageProperties, ip quote.InfrastructureProperties) error {
	// Verify Quote
	report, err := enclave.VerifyRemoteReport(givenQuote)
	if err != nil {
		return fmt.Errorf("verifying quote failed: %v", err)
	}

	// Check that cert is equal
	hash := sha256.Sum256(cert)
	if !bytes.Equal(report.Data[:len(hash)], hash[:]) {
		return fmt.Errorf("hash(cert) != report.Data: %v != %v", hash, report.Data)
	}

	// Verify PackageProperties
	productID := binary.LittleEndian.Uint64(report.ProductID)
	reportedProps := quote.PackageProperties{
		UniqueID:        hex.EncodeToString(report.UniqueID),
		SignerID:        hex.EncodeToString(report.SignerID),
		Debug:           report.Debug,
		ProductID:       &productID,
		SecurityVersion: &report.SecurityVersion,
	}
	if !pp.IsCompliant(reportedProps) {
		return fmt.Errorf("PackageProperties not compliant:\n%v\n%v", reportedProps, pp)
	}

	// TODO Verify InfrastructureProperties with information from OE Quote
	return nil
}

// ERTIssuer is a Quote issuer based on EdgelessRT.
type ERTIssuer struct{}

// NewERTIssuer returns a new ERTIssuer object.
func NewERTIssuer() *ERTIssuer {
	return &ERTIssuer{}
}

// Issue implements the Issuer interface.
func (m *ERTIssuer) Issue(cert []byte) ([]byte, error) {
	hash := sha256.Sum256(cert)
	return enclave.GetRemoteReport(hash[:])
}
