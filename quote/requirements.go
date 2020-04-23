package quote

import (
	"github.com/google/go-cmp/cmp"
)

// InfrastructureRequirements defines the requirements for the infrastructure
type InfrastructureRequirements struct {
	InfrastructureProperties
	requirements
}

// PackageRequirements defines the requirements for an enclave package
type PackageRequirements struct {
	PackageProperties
	requirements
}

type requirements struct {
	// If true, SVNs that are higher than specified are not accepted.
	StrictSVN bool
}

// IsCompliant checks if the given package properties comply with the requirements
func (req PackageRequirements) IsCompliant(prop PackageProperties) bool {
	if req.StrictSVN {
		return cmp.Equal(req, prop)
	}
	if !cmp.Equal(req.basicPackageProperties, prop.basicPackageProperties) {
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
	if !cmp.Equal(req.basicInfrastructureProperties, prop.basicInfrastructureProperties) {
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
