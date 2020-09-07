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
	return cmp.Equal(required, given)
}

// IsCompliant checks if the given infrastructure properties comply with the requirements
func (required InfrastructureProperties) IsCompliant(given InfrastructureProperties) bool {
	// TODO: implement proper logic including SVN comparison
	return cmp.Equal(required, given)
}
