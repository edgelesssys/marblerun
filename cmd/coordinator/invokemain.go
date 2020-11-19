// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
