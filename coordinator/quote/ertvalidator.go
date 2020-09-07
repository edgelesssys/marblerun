package quote

import (
	"bytes"
	"fmt"

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
func (m *ERTValidator) Validate(quote []byte, message []byte, pp PackageProperties, ip InfrastructureProperties) error {
	// Verify Quote
	report, err := ertenclave.VerifyRemoteReport(quote)
	if err != nil {
		return fmt.Errorf("verifying quote failed: %v", err)
	}

	// Check that message is equal
	if !bytes.Equal(message, report.Data) {
		return fmt.Errorf("message != report.Data: %v != %v", message, report.Data)
	}

	// Verify PackageProperties
	reportedProps := PackageProperties{
		UniqueID:        report.UniqueID,
		SignerID:        report.SignerID,
		Debug:           report.Debug,
		ProductID:       report.ProductID,
		SecurityVersion: &report.SecurityVersion,
	}
	if !pp.IsCompliant(reportedProps) {
		return fmt.Errorf("PackageProperties not compliant")
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
func (m *ERTIssuer) Issue(message []byte) ([]byte, error) {
	return ertenclave.GetRemoteReport(message)
}
