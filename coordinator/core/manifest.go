package coordinator

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
	// Allowed node configurations
	Nodes map[string]Node
	// Authorized client x509 certificates
	Clients map[string][]byte
}

// Node describes a type of a node
type Node struct {
	Package        string
	MaxActivations uint
	Parameters     rpc.Parameters
}
