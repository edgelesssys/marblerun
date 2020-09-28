package main

// #cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-in-object-files
// void mountData(const char* path);
import "C"

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/edgelesssys/coordinator/coordinator/config"
	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/quote/ertvalidator"
	"github.com/edgelesssys/coordinator/coordinator/server"
	"github.com/edgelesssys/ertgolib/ertenclave"
)

func main() {}

func mountData(path string) {
	C.mountData((*C.char)(unsafe.Pointer(&[]byte(path)[0])))
}

func coordinatormain(cwd string) {
	// initialize coordinator
	validator := ertvalidator.NewERTValidator()
	issuer := ertvalidator.NewERTIssuer()
	sealKey, _, err := ertenclave.GetProductSealKey()
	if err != nil {
		panic(err)
	}
	sealDir := os.Getenv(config.EdgCoordinatorSealDir)
	if len(sealDir) == 0 {
		panic(fmt.Errorf("environment variable not set: %v", config.EdgCoordinatorSealDir))
	}
	if err := os.MkdirAll(sealDir, 0700); err != nil {
		panic(err)
	}
	sealer := core.NewAESGCMSealer(sealDir, sealKey)
	core, err := core.NewCore("Coordinator", validator, issuer, sealer)
	if err != nil {
		panic(err)
	}

	// start client server
	mux := server.CreateServeMux(core)
	clientServerTLSConfig, err := core.GetTLSConfig()
	if err != nil {
		panic(err)
	}
	clientServerAddr := os.Getenv(config.EdgClientServerAddr)
	if len(clientServerAddr) == 0 {
		panic(fmt.Errorf("environment variable not set: %v", config.EdgClientServerAddr))
	}
	go server.RunClientServer(mux, clientServerAddr, clientServerTLSConfig)

	// run marble server
	addrChan := make(chan string)
	errChan := make(chan error)
	meshServerAddr := os.Getenv(config.EdgMeshServerAddr)
	if len(meshServerAddr) == 0 {
		panic(fmt.Errorf("environment variable not set: %v", config.EdgMeshServerAddr))
	}
	go server.RunMarbleServer(core, meshServerAddr, addrChan, errChan)
	for {
		select {
		case err := <-errChan:
			if err != nil {
				panic(err)
			}
			return
		case grpcAddr := <-addrChan:
			fmt.Println("start mesh server at ", grpcAddr)
		}
	}
}
