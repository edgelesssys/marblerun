package main

// #cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-in-object-files
// void mountData(const char* path);
import "C"

import (
	"fmt"
	"os"
	"strings"
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

func coordinatormain() {
	// initialize coordinator
	validator := ertvalidator.NewERTValidator()
	issuer := ertvalidator.NewERTIssuer()
	sealKey, _, err := ertenclave.GetProductSealKey()
	if err != nil {
		panic(err)
	}
	sealDir := util.MustGetenv(config.EdgCoordinatorSealDir)
	dnsNames := []string{"localhost"}
	dnsNamesString := util.MustGetenv(config.EdgCoordinatorDNSNames)
	dnsNames = strings.Split(dnsNamesString, ",")
	clientServerAddr := util.MustGetenv(config.EdgClientServerAddr)
	meshServerAddr := util.MustGetenv(config.EdgMeshServerAddr)

	if err := os.MkdirAll(sealDir, 0700); err != nil {
		panic(err)
	}
	dnsNames := []string{"localhost"}
	dnsNamesString := os.Getenv(config.EdgCoordinatorDNSNames)
	if len(dnsNamesString) > 0 {
		dnsNames = strings.Split(dnsNamesString, ",")
	}
	sealer := core.NewAESGCMSealer(sealDir, sealKey)
	core, err := core.NewCore("Coordinator", dnsNames, validator, issuer, sealer)
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
