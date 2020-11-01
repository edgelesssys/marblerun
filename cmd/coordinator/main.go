// Copyright (c) Edgeless Systems GmbH.
// Licensed under the MIT License.

// +build !enclave

package main

import "github.com/edgelesssys/coordinator/coordinator/quote"

func main() {
	validator := quote.NewFailValidator()
	issuer := quote.NewFailIssuer()
	sealKey := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	run(validator, issuer, sealKey, "")
}
