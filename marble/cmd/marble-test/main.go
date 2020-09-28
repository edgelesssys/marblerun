package main

// #cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-in-object-files
// void mountData(const char* path);
import "C"

import (
	"fmt"
	"log"
	"os"
	"unsafe"

	"github.com/edgelesssys/coordinator/marble/cmd/common"
	"github.com/edgelesssys/coordinator/marble/marble"
)

const (
	Success             int = 0
	InternalError       int = 2
	AuthenticationError int = 4
	UsageError          int = 8
)

func main() {}

func mountData(path string) {
	C.mountData((*C.char)(unsafe.Pointer(&[]byte(path)[0])))
}

//export ert_meshentry_premain
func ert_meshentry_premain(argc *C.int, argv ***C.char) {
	// call PreMain
	err := marble.PreMain()
	if err != nil {
		panic(err)
	}
	ret := common.PremainTarget(len(os.Args), os.Args, os.Environ())
	if ret != 0 {
		panic(fmt.Errorf("premainTarget returned: %v", ret))
	}
	log.Println("Successfully authenticated with Coordinator!")
}
