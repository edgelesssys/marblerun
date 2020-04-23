package quote

import (
	"errors"

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
func (req *PackageRequirements) CheckCompliance(prop *PackageProperties) error {
	if req.HigherSVNOK {
		// TODO: implement SVN comparison
		return errors.New("SVN comparison is not implemented")
	}
	if !cmp.Equal(&req.PackageProperties, prop) {
		return errors.New("package does not comply")
	}
	return nil
}

// CheckCompliance checks if the given infrastructure properties comply with the requirements
func (req *InfrastructureRequirements) CheckCompliance(prop *InfrastructureProperties) error {
	if req.HigherSVNOK {
		// TODO: implement SVN comparison
		return errors.New("SVN comparison is not implemented")
	}
	if !cmp.Equal(&req.InfrastructureProperties, prop) {
		return errors.New("package does not comply")
	}
	return nil
}
