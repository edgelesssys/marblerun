package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/server"
)

func main() {
	configPath := flag.String("c", "", "config file path")
	flag.Parse()
	cfg := struct {
		MeshServerAddr   string
		ClientServerAddr string
		DataPath         string
	}{
		"localhost:25554",
		"localhost:25555",
		"/tmp/edg_coordinator_0",
	}
	if *configPath == "" {
		panic(fmt.Errorf("no valid config path provided"))
	}
	config, err := ioutil.ReadFile(*configPath)
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(config, &cfg); err != nil {
		panic(err)
	}

	// initialize coordinator
	validator := quote.NewFailValidator()
	issuer := quote.NewFailIssuer()
	sealKey := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	sealDir := filepath.Join(cfg.DataPath, "sealing")
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
