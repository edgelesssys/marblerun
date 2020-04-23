package coordinator

import (
	"edgeless.systems/mesh/coordinator/quote"
	"edgeless.systems/mesh/coordinator/rpc"
)

type requirements struct {
	HigherSVNOK bool
}

// InfrastructureRequirements defines the requirements for the infrastructure
type InfrastructureRequirements struct {
	quote.InfrastructureProperties
	requirements
}

// PackageRequirements defines the requirements for an enclave package
type PackageRequirements struct {
	quote.PackageProperties
	requirements
}

// Manifest defines the rules of a mesh.
type Manifest struct {
	// Allowed enclave packages
	Packages map[string]PackageRequirements
	// Allowed infrastructures
	Infrastructures map[string]InfrastructureRequirements
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
