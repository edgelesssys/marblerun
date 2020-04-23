package quote

import "github.com/google/go-cmp/cmp"

// BasicPackageProperties contains the enclave package-specific properties of a SGX DCAP quote that are not SVNs.
type BasicPackageProperties struct {
	MiscSelect *uint32
	Attributes *[16]byte
	MRSigner   *[32]byte
	MREnclave  *[32]byte
	// Product ID of the package
	ISVProdID *uint16
}

// PackageProperties contains the enclave package-specific properties of a SGX DCAP quote.
// In most cases, one should either specify MREnclave or MRSigner, ISVPRODID, and ISVSVN.
type PackageProperties struct {
	BasicPackageProperties
	// Security version number of the package
	ISVSVN *uint16
}

// BasicInfrastructureProperties contains the infrastructure-specific properties of a SGX DCAP quote that are not SVNs.
type BasicInfrastructureProperties struct {
	// Processor model and firmware security version number
	// NOTE: the Intel manual states that CPUSVN "cannot be compared mathematically"
	CPUSVN *[16]byte
	// Certificate of the root CA
	RootCA []byte
}

// InfrastructureProperties contains the infrastructure-specific properties of a SGX DCAP quote.
type InfrastructureProperties struct {
	BasicInfrastructureProperties
	// Quoting Enclave security version number
	QESVN *uint16
	// Provisioning Certification Enclave security version number
	PCESVN *uint16
}

// IsCompliant checks if the given package properties comply with the requirements
func (requirements PackageProperties) IsCompliant(prop PackageProperties) bool {
	if !cmp.Equal(req.BasicPackageProperties, prop.BasicPackageProperties) {
		return false
	}
	if prop.ISVSVN < req.ISVSVN {
		return false
	}
	return true
}

// IsCompliant checks if the given infrastructure properties comply with the requirements
func (req InfrastructureRequirements) IsCompliant(prop InfrastructureProperties) bool {
	if req.StrictSVN {
		return cmp.Equal(req, prop)
	}
	if !cmp.Equal(req.BasicInfrastructureProperties, prop.BasicInfrastructureProperties) {
		return false
	}
	if prop.QESVN < req.QESVN {
		return false
	}
	if prop.PCESVN < req.PCESVN {
		return false
	}
	return true
}
