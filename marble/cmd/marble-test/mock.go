// Copyright (c) Edgeless Systems GmbH.
// Licensed under the MIT License.

// +build !enclave

package main

import "github.com/edgelesssys/coordinator/marble/marble"

func init() {
	if err := marble.PreMainMock(); err != nil {
		panic(err)
	}
}
