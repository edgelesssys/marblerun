package core

import (
	"context"
	"errors"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/rpc"
)

// RootCAPlaceholder is a Manifest placeholder variable for the Coordinator's root certificate
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

//Check if manifest is consistent
func (m Manifest) Check(ctx context.Context) error {
	if len(m.Packages) <= 0 {
		return errors.New("No allowed packages defined")
	}
	if len(m.Marbles) <= 0 {
		return errors.New("No allowed marbles defined")
	}
	if len(m.Infrastructures) <= 0 {
		return errors.New("No allowed infrastructures defined")
	}
	for _, marble := range m.Marbles {
		if _, ok := m.Packages[marble.Package]; !ok {
			return errors.New("Manifest does not contain marble package " + marble.Package)
		}
	}
	return nil
}
