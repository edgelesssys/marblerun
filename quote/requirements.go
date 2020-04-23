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
	// If true, SVNs that are higher than the specified one are accepted.
	HigherSVNOK bool
}

// CheckCompliance checks if the given package properties comply with the requirements
func (req *PackageRequirements) CheckCompliance(prop *PackageProperties) bool {
	if !req.HigherSVNOK {
		return cmp.Equal(req, prop)
	}
	// TODO: implement SVN comparison
	return false
}

// CheckCompliance checks if the given infrastructure properties comply with the requirements
func (req *InfrastructureRequirements) CheckCompliance(prop *InfrastructureProperties) bool {
	if !req.HigherSVNOK {
		return cmp.Equal(req, prop)
	}
	// TODO: implement SVN comparison
	return false
}
