// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package quote

import (
	"bytes"
	"strings"

	"github.com/google/go-cmp/cmp"
)

// PackageProperties contains the enclave package-specific properties of an OpenEnclave quote
// Either UniqueID or SignerID, ProductID, and SecurityVersion should be specified.
type PackageProperties struct {
	// Debug Flag of the Attributes.
	Debug bool
	// Hash of the enclave.
	UniqueID string
	// Hash of the enclave signer's public key.
	SignerID string
	// Product ID of the package.
	ProductID *uint64
	// Security version number of the package.
	SecurityVersion *uint
	// Accepted TCB levels
	AcceptedTCBStatuses []string
}

// InfrastructureProperties contains the infrastructure-specific properties of a SGX DCAP quote.
type InfrastructureProperties struct {
	// Processor model and firmware security version number.
	// NOTE: the Intel manual states that CPUSVN "cannot be compared mathematically"
	CPUSVN []byte
	// Quoting Enclave security version number.
	QESVN *uint16
	// Provisioning Certification Enclave security version number.
	PCESVN *uint16
	// Certificate of the root CA (not optional).
	RootCA []byte
}

// Equal returns true if both packages are equal.
func (p PackageProperties) Equal(other PackageProperties) bool {
	if p.Debug != other.Debug || p.UniqueID != other.UniqueID || p.SignerID != other.SignerID {
		return false
	}

	if p.ProductID == nil && other.ProductID != nil || p.ProductID != nil && other.ProductID == nil {
		return false
	}
	if p.ProductID != nil && other.ProductID != nil && *p.ProductID != *other.ProductID {
		return false
	}

	if p.SecurityVersion == nil && other.SecurityVersion != nil || p.SecurityVersion != nil && other.SecurityVersion == nil {
		return false
	}
	if p.SecurityVersion != nil && other.SecurityVersion != nil && *p.SecurityVersion != *other.SecurityVersion {
		return false
	}

	return true
}

// IsCompliant checks if the given package properties comply with the requirements.
func (required PackageProperties) IsCompliant(given PackageProperties) bool {
	if required.Debug != given.Debug {
		return false
	}
	if len(required.UniqueID) > 0 && !strings.EqualFold(required.UniqueID, given.UniqueID) {
		return false
	}
	if len(required.SignerID) > 0 && !strings.EqualFold(required.SignerID, given.SignerID) {
		return false
	}
	if required.ProductID != nil && *required.ProductID != *given.ProductID {
		return false
	}
	if required.SecurityVersion != nil && *required.SecurityVersion > *given.SecurityVersion {
		return false
	}
	return true
}

// Equal returns true if both infrastructures are equal.
func (p InfrastructureProperties) Equal(other InfrastructureProperties) bool {
	if !bytes.Equal(p.CPUSVN, other.CPUSVN) || !bytes.Equal(p.RootCA, other.RootCA) {
		return false
	}

	if p.QESVN == nil && other.QESVN != nil || p.QESVN != nil && other.QESVN == nil {
		return false
	}
	if p.QESVN != nil && other.QESVN != nil && *p.QESVN != *other.QESVN {
		return false
	}

	if p.PCESVN == nil && other.PCESVN != nil || p.PCESVN != nil && other.PCESVN == nil {
		return false
	}
	if p.PCESVN != nil && other.PCESVN != nil && *p.PCESVN != *other.PCESVN {
		return false
	}

	return true
}

// IsCompliant checks if the given infrastructure properties comply with the requirements.
func (required InfrastructureProperties) IsCompliant(given InfrastructureProperties) bool {
	// TODO: implement proper logic including SVN comparison
	return cmp.Equal(required, given)
}
