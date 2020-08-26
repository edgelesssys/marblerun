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
	// Allowed pod configurations
	Pods map[string]Pod
	// Authorized client x509 certificates
	Clients map[string][]byte
}

// Pod describes a type of a pod
type Pod struct {
	Package        string
	MaxActivations uint
	Parameters     rpc.Parameters
}
