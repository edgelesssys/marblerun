package main

import (
	"flag"
	"fmt"

	_core "github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/server"
)

func main() {
	meshServerAddr := flag.String("ip", "localhost:0", "")
	clientServerAddr := flag.String("ep", "localhost:25555", "")
	flag.Parse()

	// coordinator setup
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	core, _ := _core.NewCore("Coordinator", validator, issuer)

	// start client server
	fmt.Println("start client server at", *clientServerAddr)
	mux := server.CreateServeMux(core)
	go server.RunServer(mux, *clientServerAddr, nil)

	// run mesh server
	var err error
	var grpcAddr string
	addrChan := make(chan string)
	errChan := make(chan error)
	go server.RunMeshServer(core, *meshServerAddr, addrChan, errChan)
	select {
	case err = <-errChan:
		fmt.Println("Failed to start gRPC server", err)
	case grpcAddr = <-addrChan:
		fmt.Println("start mesh server at", grpcAddr)
	}
	for {
	}
}
