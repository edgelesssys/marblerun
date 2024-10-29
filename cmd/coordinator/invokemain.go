//go:build enclave

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import "C"

//export invokemain
func invokemain() {
	main()
}

//export ert_meshentry_premain
func ert_meshentry_premain(argc *C.int, argv ***C.char) {
}
