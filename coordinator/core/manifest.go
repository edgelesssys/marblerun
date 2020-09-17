package core

import (
	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/rpc"
)

// RootCAPlaceholder is a Manifest placeholder variable for the RootCAPlaceholder
const RootCAPlaceholder string = "$$root_ca"

// MarbleCertPlaceholder is a Manifest placeholder variable for the Marble's Certificate
const MarbleCertPlaceholder string = "$$marble_cert"

// MarbleKeyPlaceholder is a Manifest placeholder variable for the Marble's Private Key
const MarbleKeyPlaceholder string = "$$marble_key"

// SealKeyPlaceholder is a Manifest placeholder variable for the Marble's Sealing Key
const SealKeyPlaceholder string = "$$seal_key"

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
