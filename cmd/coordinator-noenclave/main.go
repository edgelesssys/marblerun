package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/edgelesssys/coordinator/coordinator/config"
	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/server"
)

func main() {
	// initialize coordinator
	validator := quote.NewFailValidator()
	issuer := quote.NewFailIssuer()
	sealKey := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	sealDir := os.Getenv(config.EdgCoordinatorSealDir)
	if len(sealDir) == 0 {
		panic(fmt.Errorf("environment variable not set: %v", config.EdgCoordinatorSealDir))
	}
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
