// Copyright (c) Edgeless Systems GmbH.
// Licensed under the MIT License.

// +build enclave

package main

import "C"

//export invokemain
func invokemain() {
	main()
}

//export ert_meshentry_premain
func ert_meshentry_premain(argc *C.int, argv ***C.char) {
}
