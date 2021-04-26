// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

// #include <stdlib.h>
import "C"

import (
	"fmt"
	"os"
	"strings"

	marblePremain "github.com/edgelesssys/marblerun/marble/premain"
	"github.com/spf13/afero"
)

func main() {}

//export premain
func premain() {
	// filter env vars
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "EDG_") && !strings.HasPrefix(env, "LD_LIBRARY_PATH=") {
			if err := C.unsetenv(C.CString(strings.SplitN(env, "=", 2)[0])); int(err) != 0 {
				panic(fmt.Errorf("unsetenv returned the following error code: %d", int(err)))
			}
		}
	}

	hostfs := afero.NewOsFs()
	if err := marblePremain.PreMainEx(marblePremain.GrapheneQuoteIssuer{}, marblePremain.GrapheneActivate, hostfs, hostfs); err != nil {
		panic(err)
	}
}
