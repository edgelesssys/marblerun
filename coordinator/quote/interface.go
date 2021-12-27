// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
