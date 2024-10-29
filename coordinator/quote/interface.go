/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// Package quote provides the quoting functionialty for remote attestation on both Coordinator and Marble site.
package quote

// Validator validates quotes.
type Validator interface {
	// Validate validates a quote for a given message and properties
	Validate(quote []byte, cert []byte, pp PackageProperties, ip InfrastructureProperties) error
}

// Issuer issues quotes.
type Issuer interface {
	// Issue issues a quote for remote attestation for a given message
	Issue(cert []byte) (quote []byte, err error)
}
