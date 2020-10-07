package main

// #cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-in-object-files
// void mountData(const char* path);
import "C"

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/quote/ertvalidator"
	"github.com/edgelesssys/coordinator/coordinator/server"
	"github.com/edgelesssys/ertgolib/ertenclave"
)

func main() {}

func mountData(path string) {
	C.mountData((*C.char)(unsafe.Pointer(&[]byte(path)[0])))
}

func coordinatormain() {
	log.SetPrefix("[Coordinator]")
	log.Println("starting coordinator")
	// initialize coordinator
	validator := ertvalidator.NewERTValidator()
	issuer := ertvalidator.NewERTIssuer()
	sealKey, _, err := ertenclave.GetProductSealKey()
	if err != nil {
		panic(err)
	}
	sealDir := util.MustGetenv(config.EdgCoordinatorSealDir)
	sealDir = filepath.Join(filepath.FromSlash("/edg"), "hostfs", sealDir)
	dnsNamesString := util.MustGetenv(config.EdgCoordinatorDNSNames)
	dnsNames := strings.Split(dnsNamesString, ",")
	clientServerAddr := util.MustGetenv(config.EdgClientServerAddr)
	meshServerAddr := util.MustGetenv(config.EdgMeshServerAddr)

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
	go server.RunClientServer(mux, clientServerAddr, clientServerTLSConfig)

	// run marble server
	addrChan := make(chan string)
	errChan := make(chan error)
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
