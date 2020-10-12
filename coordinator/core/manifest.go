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
	// Packages contains the allowed enclaves and their properties.
	Packages map[string]quote.PackageProperties
	// Infrastructures contains the allowed infrastructure providers and their properties.
	Infrastructures map[string]quote.InfrastructureProperties
	// Marbles contains the allowed services with their corresponding enclave and configuration parameters.
	Marbles map[string]Marble
	// Clients contains TLS certificates for authenticating clients that use the ClientAPI.
	Clients map[string][]byte
}

// Marble describes a service in the mesh that should be handled and verified by the Coordinator
//
// Package references one of the allowed enclaves in the manifest.
// MaxActivations allows to limit the number of marbles of a kind.
// Parameters contains lists for files, environment variables and commandline arguments that should be passed to the application. Placeholder variables are supported for specific assets of the marble's activation process.
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
