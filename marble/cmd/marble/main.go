package main

// #cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-in-object-files
// void mountData(const char* path);
import "C"

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/edgelesssys/coordinator/marble/marble"
)

var cargs []*C.char

func main() {}

func mountData(path string) {
	C.mountData((*C.char)(unsafe.Pointer(&[]byte(path)[0])))
}

//export ert_meshentry_premain
func ert_meshentry_premain(configStr *C.char, argc *C.int, argv ***C.char) {
	config := C.GoString(configStr)

	cfg := struct {
		CoordinatorAddr string
		MarbleType      string
		DNSNames        string
		DataPath        string
	}{}
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		panic(err)
	}
	// mount data dir
	mountData(cfg.DataPath) // mounts DataPath to /marble/data
	// set env vars
	if err := os.Setenv(marble.EdgCoordinatorAddr, cfg.CoordinatorAddr); err != nil {
		log.Fatalf("failed to set env variable: %v", err)
		return
	}
	if err := os.Setenv(marble.EdgMarbleType, cfg.MarbleType); err != nil {
		log.Fatalf("failed to set env variable: %v", err)
		return
	}

	if err := os.Setenv(marble.EdgMarbleDNSNames, cfg.DNSNames); err != nil {
		log.Fatalf("failed to set env variable: %v", err)
		return
	}
	uuidFile := filepath.Join("marble", "data", "uuid")
	if err := os.Setenv(marble.EdgMarbleUUIDFile, uuidFile); err != nil {
		log.Fatalf("failed to set env variable: %v", err)
		return
	}

	if err := marble.PreMain(); err != nil {
		panic(err)
	}

	cargs = make([]*C.char, len(os.Args)+1)
	for i, a := range os.Args {
		cargs[i] = C.CString(a)
	}

	*argc = C.int(len(os.Args))
	*argv = &cargs[0]
}
