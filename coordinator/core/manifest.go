package core

import (
	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/rpc"
)

// Manifest defines the rules of a mesh.
type Manifest struct {
	// Allowed enclave packages
	Packages map[string]quote.PackageProperties
	// Allowed infrastructures
	Infrastructures map[string]quote.InfrastructureProperties
	// Allowed marble configurations
	Marbles map[string]Marble
	// Authorized client x509 certificates
	Clients map[string][]byte
}

// Marble describes a type of a marble
type Marble struct {
	Package        string
	MaxActivations uint
	Parameters     rpc.Parameters
}
