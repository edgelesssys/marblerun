package main

import (
	"encoding/json"
	"log"
)

// Manifest defines allowed nodes in a mesh
type Manifest struct {
	Packages    map[string]Package
	Attestation struct {
		MinSVN  []byte
		RootCAs map[string]Cert
	}
	Nodes   map[string]Node
	Clients map[string]Cert
}

// Cert is the certificate that identifies a party
type Cert []byte

// Package defines an allowed package
type Package struct {
	MRSigner  []byte
	MREnclave []byte
}

// Node describes a type of a node
type Node struct {
	Package        string
	MaxActivations int
	Parameters     struct {
		env   map[string]string
		argv  []string
		files map[string][]byte
	}
}

func main() {
	m := Manifest{
		Packages: map[string]Package{
			"tikv": {
				MRSigner: []byte{0, 1, 2},
			},
		},
	}
	b, err := json.Marshal(m)
	if err != nil {
		log.Fatalf("Failed to marshal: %v", err)
	}
	log.Println(string(b))
	log.Println(b)
	var m1 Manifest
	if err = json.Unmarshal([]byte(string(b)), &m1); err != nil {
		log.Fatalf("Failed to unmarshal: %v", err)
	}
	log.Println(m1.Packages["tikv"].MRSigner[1])
	s := "{\"Packages\":{\"tikv\":{\"MRSigner\":\"AAEC\"}},\"Attestation\":{\"MinSVN\":null,\"RootCAs\":null}}"
	var m2 Manifest
	if err = json.Unmarshal([]byte(s), &m2); err != nil {
		log.Fatalf("Failed to unmarshal: %v", err)
	}
	log.Println(m2.Packages["tikv"].MRSigner[2])
}
