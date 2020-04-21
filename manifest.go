package coordinator

import (
	"edgeless.systems/mesh/coordinator/quote"
	"edgeless.systems/mesh/coordinator/rpc"
)

// Manifest defines allowed nodes in a mesh
type Manifest struct {
	Packages    map[string]quote.Requirements
	Attestation struct {
		MinCPUSVN []byte
		RootCAs   map[string]RawCert
	}
	Nodes   map[string]Node
	Clients map[string]RawCert
}

// RawCert is the certificate that identifies a party
type RawCert []byte

// Node describes a type of a node
type Node struct {
	Package        string
	MaxActivations uint
	Parameters     rpc.Parameters
}
