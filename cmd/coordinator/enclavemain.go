// +build enclave

package main

import (
	"path/filepath"

	"github.com/edgelesssys/coordinator/coordinator/quote/ertvalidator"
	"github.com/edgelesssys/ertgolib/ertenclave"
)

func main() {
	validator := ertvalidator.NewERTValidator()
	issuer := ertvalidator.NewERTIssuer()
	sealKey, _, err := ertenclave.GetProductSealKey()
	if err != nil {
		panic(err)
	}
	sealDirPrefix := filepath.Join(filepath.FromSlash("/edg"), "hostfs")
	run(validator, issuer, sealKey, sealDirPrefix)
}
