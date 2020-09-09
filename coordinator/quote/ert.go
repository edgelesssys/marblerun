package quote

import "github.com/google/go-cmp/cmp"

// PackageProperties contains the enclave package-specific properties of an OpenEnclave quote.
// Either UniqueID or SignerID, ProductID, and SecurityVersion should be specified.
type PackageProperties struct {
	// Debug Flag of the Attributes
	Debug bool
	// Hash of the enclave
	UniqueID []byte
	// Hash of the enclave signer's public key
	SignerID []byte
	// Product ID of the package
	ProductID []byte
	// Security version number of the package
	SecurityVersion *uint
}

// InfrastructureProperties contains the infrastructure-specific properties of a SGX DCAP quote.
type InfrastructureProperties struct {
	// Processor model and firmware security version number
	// NOTE: the Intel manual states that CPUSVN "cannot be compared mathematically"
	CPUSVN []byte
	// Quoting Enclave security version number
	QESVN *uint16
	// Provisioning Certification Enclave security version number
	PCESVN *uint16
	// Certificate of the root CA (not optional)
	RootCA []byte
}

// IsCompliant checks if the given package properties comply with the requirements
func (required PackageProperties) IsCompliant(given PackageProperties) bool {
	// TODO: implement proper logic including SVN comparison
	if required.Debug != given.Debug {
		return false
	}
	if len(required.UniqueID) > 0 && !cmp.Equal(required.UniqueID, given.UniqueID) {
		return false
	}
	if len(required.SignerID) > 0 && !cmp.Equal(required.SignerID, given.SignerID) {
		return false
	}
	if len(required.ProductID) > 0 && !cmp.Equal(required.ProductID, given.ProductID[:len(required.ProductID)]) {
		return false
	}
	if required.SecurityVersion != nil && *required.SecurityVersion != *given.SecurityVersion {
		return false
	}
	return true
}

// IsCompliant checks if the given infrastructure properties comply with the requirements
func (required InfrastructureProperties) IsCompliant(given InfrastructureProperties) bool {
	// TODO: implement proper logic including SVN comparison
	return cmp.Equal(required, given)
}
