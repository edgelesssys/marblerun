package main

import (
	"encoding/json"
	"fmt"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/server"
)

func main() {}

func coordinatormain(cwd, config string) {
	cfg := struct {
		MeshServerAddr   string
		ClientServerAddr string
	}{
		"localhost:0",
		"localhost:25555",
	}

	if config != "" {
		if err := json.Unmarshal([]byte(config), &cfg); err != nil {
			panic(err)
		}
	}

	// initialize coordinator
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	core, err := core.NewCore("Coordinator", validator, issuer)
	if err != nil {
		panic(err)
	}

	// start client server
	mux := server.CreateServeMux(core)
	clientServerTLSConfig, err := core.GetTLSConfig()
	if err != nil {
		panic(err)
	}
	go server.RunClientServer(mux, cfg.ClientServerAddr, clientServerTLSConfig)

	// run marble server
	addrChan := make(chan string)
	errChan := make(chan error)
	go server.RunMarbleServer(core, cfg.MeshServerAddr, addrChan, errChan)
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
