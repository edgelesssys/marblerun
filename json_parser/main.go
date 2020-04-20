package main

import (
	"encoding/json"
	"log"

	c "edgeless.systems/mesh/coordinator"
)

func main() {
	m := c.Manifest{
		Packages: map[string]c.Package{
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
	var m1 c.Manifest
	if err = json.Unmarshal([]byte(string(b)), &m1); err != nil {
		log.Fatalf("Failed to unmarshal: %v", err)
	}
	log.Println(m1.Packages["tikv"].MRSigner[1])
	s := "{\"Packages\":{\"tikv\":{\"MRSigner\":\"AAEC\"}},\"Attestation\":{\"MinSVN\":null,\"RootCAs\":null}}"
	var m2 c.Manifest
	if err = json.Unmarshal([]byte(s), &m2); err != nil {
		log.Fatalf("Failed to unmarshal: %v", err)
	}
	log.Println(m2.Packages["tikv"].MRSigner[2])
}
