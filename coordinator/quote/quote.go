package quote

import (
	"bytes"
	"errors"

	enc "github.com/edgelesssys/ertgolib/ertenclave"
	//"github.com/edgelesssys/erthost"
)

type entry struct {
	message []byte
	pp      PackageProperties
	ip      InfrastructureProperties
}

// MockValidator is a mockup quote validator
type MockValidator struct {
	valid map[string]entry
}

// NewMockValidator .
func NewMockValidator() *MockValidator {
	return &MockValidator{
		make(map[string]entry),
	}
}

// Validate implements the Validator interface
// Input:
// 		quote: received from Activate grpc call
//		message: raw cert from TLS context
//		pkg, infra: from manifest
func (m *MockValidator) Validate(quote []byte, message []byte, pp PackageProperties, ip InfrastructureProperties) error {
	entry, found := m.valid[string(quote)]
	if !found {
		return errors.New("wrong quote")
	}
	if !bytes.Equal(entry.message, message) {
		return errors.New("wrong message")
	}
	if !pp.IsCompliant(entry.pp) {
		return errors.New("package does not comply")
	}
	if !ip.IsCompliant(entry.ip) {
		return errors.New("infrastructure does not comply")
	}
	return nil
}

// IssuerImpl is a quote issuer for its own instance
type IssuerImpl struct{}

// NewIssuerImpl .
func NewIssuerImpl() *IssuerImpl {
	return &IssuerImpl{}
}

// Issue implements the Issuer interface. Argument message will be included in the report
func (m *IssuerImpl) Issue(message []byte) ([]byte, error) {
	//hash := sha256.Sum256(message)
	return enc.GetRemoteReport(message)
}
