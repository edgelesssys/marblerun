package main

import (
	"flag"
	"fmt"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/server"
)

func main() {
	meshServerAddr := flag.String("ip", "localhost:0", "")
	clientServerAddr := flag.String("ep", "localhost:25555", "")
	flag.Parse()

	// initialize coordinator
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := core.NewMockSealer()
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
	go server.RunClientServer(mux, *clientServerAddr, clientServerTLSConfig)

	// run marble server
	addrChan := make(chan string)
	errChan := make(chan error)
	go server.RunMarbleServer(core, *meshServerAddr, addrChan, errChan)
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
