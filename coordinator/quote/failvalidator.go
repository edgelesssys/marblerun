// Copyright (c) Edgeless Systems GmbH.
// Licensed under the MIT License.

package quote

import (
	"fmt"
)

// FailValidator always fails
type FailValidator struct {
}

// NewFailValidator returns a new FailValidator object
func NewFailValidator() *FailValidator {
	return &FailValidator{}
}

// Validate implements the Validator interface for FailValidator
func (m *FailValidator) Validate(quote []byte, cert []byte, pp PackageProperties, ip InfrastructureProperties) error {
	return fmt.Errorf("cannot validate quote")
}

// FailIssuer always fails
type FailIssuer struct{}

// NewFailIssuer returns a new FailIssuer object
func NewFailIssuer() *FailIssuer {
	return &FailIssuer{}
}

// Issue implements the Issuer interface
func (m *FailIssuer) Issue(cert []byte) ([]byte, error) {
	return nil, fmt.Errorf("cannot issue quote")
}
