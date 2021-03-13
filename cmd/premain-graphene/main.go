package main

// #include <spawn.h>
// #include <sys/wait.h>
import "C"

import (
	"os"
	"strings"
	"syscall"

	marblePremain "github.com/edgelesssys/marblerun/marble/premain"
	"github.com/spf13/afero"
)

func main() {
	// filter env vars
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "EDG_") && !strings.HasPrefix(env, "LD_LIBRARY_PATH=") {
			if err := os.Unsetenv(strings.SplitN(env, "=", 2)[0]); err != nil {
				panic(err)
			}
		}
	}

	// save the passed argument which is our service to spawn
	service := os.Args[0]

	hostfs := afero.NewOsFs()
	if err := marblePremain.PreMainEx(marblePremain.GrapheneQuoteIssuer{}, marblePremain.GrapheneActivate, hostfs, hostfs); err != nil {
		panic(err)
	}

	argv := toCArray(os.Args)
	envp := toCArray(os.Environ())

	// spawn service
	if res := C.posix_spawn(nil, C.CString(service), nil, nil, &argv[0], &envp[0]); res != 0 {
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
