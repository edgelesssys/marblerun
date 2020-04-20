package coordinator

import "edgeless.systems/mesh/coordinator/quote"

// Manifest defines allowed nodes in a mesh
type Manifest struct {
	Packages    map[string]quote.Requirements
	Attestation struct {
		MinCPUSVN []byte
		RootCAs   map[string]Cert
	}
	Nodes   map[string]Node
	Clients map[string]Cert
}

// Cert is the certificate that identifies a party
type Cert []byte

// Node describes a type of a node
type Node struct {
	Package        string
	MaxActivations uint
	Parameters     struct {
		env   map[string]string
		argv  []string
		files map[string][]byte
	}
}
