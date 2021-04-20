package main

// #include <spawn.h>
// #include <sys/wait.h>
import "C"

import (
	"errors"
	"os"
	"strings"
	"syscall"

	marblePremain "github.com/edgelesssys/marblerun/marble/premain"
	"github.com/fatih/color"
	"github.com/spf13/afero"
)

func main() {
	// Exit if we do not know which service to launch
	if len(os.Args) < 2 {
		color.Red("ERROR: You need to specify your application as second argument before running the premain.")
		panic(errors.New("no service to launch specified"))
	}
	// Warn if the user supplies argv arguments which will not be passed
	if len(os.Args) > 2 {
		color.Yellow("WARNING: Specified more than two arguments via occlum run. They will not be passed to your service.")
		color.Yellow("If you want to pass these arguments, define them in the Marblerun's manifest.")
	}

	// filter env vars
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "EDG_") && !strings.HasPrefix(env, "LD_LIBRARY_PATH=") {
			if err := os.Unsetenv(strings.SplitN(env, "=", 2)[0]); err != nil {
				panic(err)
			}
		}
	}

	// save the passed argument which is our service to spawn
	service := os.Args[1]

	hostfs := afero.NewOsFs()
	if err := marblePremain.PreMainEx(marblePremain.OcclumQuoteIssuer{}, marblePremain.ActivateRPC, hostfs, hostfs); err != nil {
		panic(err)
	}

	argv := toCArray(os.Args)
	envp := toCArray(os.Environ())

	// Occlum cannot handle nil for the PID parameter ("pointer not in user space")
	spawnedPID := C.int(0)

	// spawn service
	if res := C.posix_spawn(&spawnedPID, C.CString(service), nil, nil, &argv[0], &envp[0]); res == -1 {
		color.Red("ERROR: Failed to spawn the target process.")
		color.Red("Did you use the correct path for your target application (for example: occlum run /bin/premain-occlum /bin/hello_world)?")
		color.Red("Have you allocated enough memory?")
		panic(syscall.Errno(res))
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
