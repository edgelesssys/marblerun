// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package quote

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sync"
)

type entry struct {
	message []byte
	pp      PackageProperties
	ip      InfrastructureProperties
}

// MockValidator is a mockup quote validator.
type MockValidator struct {
	mutex sync.Mutex
	valid map[string]entry
}

// NewMockValidator returns a new MockValidator object.
func NewMockValidator() *MockValidator {
	return &MockValidator{
		valid: make(map[string]entry),
	}
}

// Validate implements the Validator interface.
func (m *MockValidator) Validate(quote []byte, message []byte, pp PackageProperties, ip InfrastructureProperties) error {
	m.mutex.Lock()
	entry, found := m.valid[string(quote)]
	m.mutex.Unlock()
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

// AddValidQuote adds a valid quote.
func (m *MockValidator) AddValidQuote(quote []byte, message []byte, pp PackageProperties, ip InfrastructureProperties) {
	m.mutex.Lock()
	m.valid[string(quote)] = entry{message, pp, ip}
	m.mutex.Unlock()
}

// MockIssuer is a mockup quote issuer.
type MockIssuer struct{}

// NewMockIssuer returns a new MockIssuer object.
func NewMockIssuer() *MockIssuer {
	return &MockIssuer{}
}

// Issue implements the Issuer interface.
func (m *MockIssuer) Issue(message []byte) ([]byte, error) {
	quote := sha256.Sum256(message)
	return quote[:], nil
}
