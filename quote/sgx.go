package quote

type basicPackageProperties struct {
	MiscSelect uint32
	Attributes [16]byte
	MRSigner   [32]byte
	MREnclave  [32]byte
	// Product ID of the package
	ISVProdID uint16
}

// PackageProperties contains the enclave package-specific properties of a SGX DCAP quote.
type PackageProperties struct {
	basicPackageProperties
	// Security version number of the package
	ISVSVN uint16
}

type basicInfrastructureProperties struct {
	// Processor model and firmware security version number
	// NOTE: the Intel manual states that CPUSVN "cannot be compared mathematically"
	CPUSVN [16]byte
	// Certificate of the root CA
	RootCA map[string][]byte
}

// InfrastructureProperties contains the infrastructure-specific properties of a SGX DCAP quote.
type InfrastructureProperties struct {
	basicInfrastructureProperties
	// Quoting Enclave security version number
	QESVN uint16
	// Provisioning Certification Enclave security version number
	PCESVN uint16
}
