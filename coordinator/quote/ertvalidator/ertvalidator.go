package ertvalidator

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/ertgolib/ertenclave"
)

// ERTValidator is a Quote validatior based on EdgelessRT
type ERTValidator struct {
}

// NewERTValidator returns a new ERTValidator object
func NewERTValidator() *ERTValidator {
	return &ERTValidator{}
}

// Validate implements the Validator interface for ERTValidator
func (m *ERTValidator) Validate(givenQuote []byte, cert []byte, pp quote.PackageProperties, ip quote.InfrastructureProperties) error {
	// Verify Quote
	report, err := ertenclave.VerifyRemoteReport(givenQuote)
	if err != nil {
		return fmt.Errorf("verifying quote failed: %v", err)
	}

	// Check that cert is equal
	hash := sha256.Sum256(cert)
	if !bytes.Equal(report.Data[:len(hash)], hash[:]) {
		return fmt.Errorf("hash(cert) != report.Data: %v != %v", hash, report.Data)
	}

	// Verify PackageProperties
	reportedProps := quote.PackageProperties{
		UniqueID:        report.UniqueID,
		SignerID:        report.SignerID,
		Debug:           report.Debug,
		ProductID:       report.ProductID,
		SecurityVersion: &report.SecurityVersion,
	}
	if !pp.IsCompliant(reportedProps) {
		return fmt.Errorf("PackageProperties not compliant:\n%v\n%v", reportedProps, pp)
	}

	// TODO Verify InfrastructureProperties with information from OE Quote
	return nil
}

// ERTIssuer is a Quote issuer based on EdgelessRT
type ERTIssuer struct{}

// NewERTIssuer returns a new ERTIssuer object
func NewERTIssuer() *ERTIssuer {
	return &ERTIssuer{}
}

// Issue implements the Issuer interface
func (m *ERTIssuer) Issue(cert []byte) ([]byte, error) {
	hash := sha256.Sum256(cert)
	return ertenclave.GetRemoteReport(hash[:])
}
