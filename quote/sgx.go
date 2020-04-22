package quote

// PackageProperties contains the enclave package-specific properties of a SGX DCAP quote.
type PackageProperties struct {
	MiscSelect uint32
	Attributes [16]byte
	MRSigner   [32]byte
	MREnclave  [32]byte
	ProdID     uint16
}

// InfrastructureProperties contains the infrastructure-specific properties of a SGX DCAP quote.
type InfrastructureProperties struct {
	// Security version numbers
	SVNs struct {
		// Quoting Enclave
		QE uint16
		// Provisioning Certification Enclave
		PCE uint16
		// Processor model and firmware
		// NOTE: the Intel manual states that CPUSVN "cannot be compared mathematically"
		CPU [16]byte
	}
	// Certificate of the root CA
	RootCA map[string][]byte
}
