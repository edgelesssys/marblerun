package main

import (
	"encoding/json"
	"fmt"

	_core "github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/server"
)

func main() {}

func coordinatormain(cwd, config string) {
	cfg := struct {
		MeshServerPort   string
		ClientServerPort string
	}{
		"localhost:0",
		"localhost:25555",
	}

	if config != "" {
		if err := json.Unmarshal([]byte(config), &cfg); err != nil {
			panic(err)
		}
	}

	// coordinator setup
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	core, _ := _core.NewCore("Coordinator", validator, issuer)

	// start client server
	fmt.Println("start client server at ", cfg.ClientServerPort)
	mux := server.CreateServeMux(core)
	go server.RunServer(mux, cfg.ClientServerPort, nil)

	// run mesh server
	var err error
	var grpcAddr string
	addrChan := make(chan string)
	errChan := make(chan error)
	go server.RunMeshServer(core, cfg.MeshServerPort, addrChan, errChan)
	select {
	case err = <-errChan:
		fmt.Println("Failed to start gRPC server", err)
	case grpcAddr = <-addrChan:
		fmt.Println("start mesh server at ", grpcAddr)
	}
	for {
	}
}
