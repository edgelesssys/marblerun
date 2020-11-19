// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// +build !enclave

package main

import "github.com/edgelesssys/marblerun/marble/premain"

func init() {
	if err := premain.PreMainMock(); err != nil {
		panic(err)
	}
}
