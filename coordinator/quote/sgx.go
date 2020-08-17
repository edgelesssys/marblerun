package quote

import "github.com/google/go-cmp/cmp"

// PackageProperties contains the enclave package-specific properties of a SGX DCAP quote.
// Either MREnclave or MRSigner, ISVProdID, and ISVSVN should be specified.
type PackageProperties struct {
	MiscSelect *uint32
	Attributes *[16]byte

	// Hash of the enclave
	MREnclave *[32]byte

	// Hash of the enclave signer's public key
	MRSigner *[32]byte
	// Product ID of the package
	ISVProdID *uint16
	// Security version number of the package
	ISVSVN *uint16
	// Flag wether validation should allow debug quotes
	allowDebug bool
}

// InfrastructureProperties contains the infrastructure-specific properties of a SGX DCAP quote.
type InfrastructureProperties struct {
	// Processor model and firmware security version number
	// NOTE: the Intel manual states that CPUSVN "cannot be compared mathematically"
	CPUSVN *[16]byte
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
