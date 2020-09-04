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
	report, err := ertenclave.VerifyRemoteReport(quote)
	if err != nil {
		return fmt.Errorf("verifying quote failed: %v", err)
	}
	if !bytes.Equal(message, report.Data) {
		return fmt.Errorf("message != report.Data: %v != %v", message, report.Data)
	}
	if pp.UniqueID != nil && !bytes.Equal((*pp.UniqueID)[:], report.UniqueID) {
		return fmt.Errorf("manifest.UniqueID != report.UniqueID: %v != %v", *pp.UniqueID, report.UniqueID)
	}
	if pp.SignerID != nil && !bytes.Equal((*pp.SignerID)[:], report.SignerID) {
		return fmt.Errorf("manifest.SignerID != report.SignerID: %v != %v", *pp.SignerID, report.SignerID)
	}
	if pp.ProductID != nil && !bytes.Equal(pp.ProductID[:], report.ProductID) {
		return fmt.Errorf("manifest.ProductID != report.ProductID: %v != %v", *pp.ProductID, report.ProductID)
	}
	if pp.SecurityVersion != nil && *pp.SecurityVersion != report.SecurityVersion {
		return fmt.Errorf("manifest.SecurityVersion != report.ISVSVN: %v != %v", *pp.SecurityVersion, report.SecurityVersion)
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
