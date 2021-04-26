// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

// #include <spawn.h>
// #include <sys/wait.h>
import "C"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	marblePremain "github.com/edgelesssys/marblerun/marble/premain"
	"github.com/fatih/color"
	"github.com/spf13/afero"
)

func main() {
	// Run Marblerun premain, add argv & envp from manifest
	hostfs := afero.NewOsFs()
	if err := marblePremain.PreMainEx(marblePremain.OcclumQuoteIssuer{}, marblePremain.ActivateRPC, hostfs, hostfs); err != nil {
		panic(err)
	}

	// Check if the entrypoint defined in os.Args[0] actually exists
	if _, err := os.Stat(os.Args[0]); os.IsNotExist(err) {
		color.Red("ERROR: The entrypoint does not seem to exist: '$%s'", os.Args[0])
		color.Red("Please make sure that you define a valid entrypoint in your manifest (for example: /bin/hello_world).")
		panic(errors.New("invalid entrypoint definition in argv[0]"))
	}

	// Modify os.Args[0] / argv[0] to only hold the program name, not the whole path, but keep it as service so we can correctly spawn the application.
	service := os.Args[0]
	os.Args[0] = filepath.Base(os.Args[0])

	argv := toCArray(os.Args)
	envp := toCArray(os.Environ())

	// Occlum cannot handle nil for the PID parameter ("pointer not in user space")
	var spawnedPID C.int

	fmt.Printf("Exiting PreMain. Launching: %s\n", service)
	// spawn service
	if res := C.posix_spawn(&spawnedPID, C.CString(service), nil, nil, &argv[0], &envp[0]); res == -1 {
		color.Red("ERROR: Failed to spawn the target process.")
		color.Red("Did you specify the correct target application in the Marblerun manifest as argv[0]?")
		color.Red("Have you allocated enough memory?")
		panic(errors.New("posix_spawn failed with error code -1"))
	} else if res != 0 {
		panic(syscall.Errno(res))
	}
	C.wait(nil)
}

func toCArray(arr []string) []*C.char {
	result := make([]*C.char, len(arr)+1)
	for i, s := range arr {
		result[i] = C.CString(s)
	}
	return result
}
