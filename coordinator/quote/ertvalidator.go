package quote

import (
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
	report, err := ertenclave.VerifyRemoteReport(quote)
	if err != nil {
		return fmt.Errorf("verifying quote failed: %v", err)
	}
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
