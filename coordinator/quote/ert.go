// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package quote

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/google/go-cmp/cmp"
)

// PackageProperties contains the enclave package-specific properties of an OpenEnclave quote
// Either UniqueID or SignerID, ProductID, and SecurityVersion should be specified.
type PackageProperties struct {
	// Debug Flag of the Attributes.
	Debug bool
	// UniqueID is a hash of the enclave (MR_ENCLAVE).
	UniqueID string
	// SignerID is a hash of the enclave signer's public key (MR_SIGNER).
	SignerID string
	// ProductID of the package (ISVPRODID).
	ProductID *uint64
	// SecurityVersion of the package (ISVSVN).
	SecurityVersion *uint
	// AcceptedTCBStatuses is a list of TCB levels an enclave is allowed to have.
	AcceptedTCBStatuses []string
}

// InfrastructureProperties contains the infrastructure-specific properties of a SGX DCAP quote.
type InfrastructureProperties struct {
	// CPUSVN is the processor model and firmware security version number.
	// NOTE: the Intel manual states that CPUSVN "cannot be compared mathematically"
	CPUSVN []byte
	// QESVN is the quoting Enclave security version number.
	QESVN *uint16
	// PCESVN is the provisioning Certification Enclave security version number.
	PCESVN *uint16
	// RootCA is the Certificate of the root Certificate Authority (not optional).
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
func (p PackageProperties) IsCompliant(given PackageProperties) bool {
	if p.Debug != given.Debug {
		return false
	}
	if len(p.UniqueID) > 0 && !strings.EqualFold(p.UniqueID, given.UniqueID) {
		return false
	}
	if len(p.SignerID) > 0 && !strings.EqualFold(p.SignerID, given.SignerID) {
		return false
	}
	if p.ProductID != nil && *p.ProductID != *given.ProductID {
		return false
	}
	if p.SecurityVersion != nil && *p.SecurityVersion > *given.SecurityVersion {
		return false
	}
	return true
}

// String returns a string representation of the package properties.
func (p PackageProperties) String() string {
	values := []string{
		fmt.Sprintf("Debug: %t", p.Debug),
	}
	if p.UniqueID != "" {
		values = append(values, fmt.Sprintf("UniqueID: %q", p.UniqueID))
	}
	if p.SignerID != "" {
		values = append(values, fmt.Sprintf("SignerID: %q", p.SignerID))
	}
	if p.ProductID != nil {
		values = append(values, fmt.Sprintf("ProductID: %d", *p.ProductID))
	}
	if p.SecurityVersion != nil {
		values = append(values, fmt.Sprintf("SecurityVersion: %d", *p.SecurityVersion))
	}
	if len(p.AcceptedTCBStatuses) > 0 {
		values = append(values, fmt.Sprintf("AcceptedTCBStatuses: %v", p.AcceptedTCBStatuses))
	}
	return fmt.Sprintf("{%s}", strings.Join(values, ", "))
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
func (p InfrastructureProperties) IsCompliant(given InfrastructureProperties) bool {
	// TODO: implement proper logic including SVN comparison
	return cmp.Equal(p, given)
}
