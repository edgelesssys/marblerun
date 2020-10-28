// +build !enclave

package main

import "github.com/edgelesssys/coordinator/marble/marble"

func init() {
	if err := marble.PreMainMock(); err != nil {
		panic(err)
	}
}
