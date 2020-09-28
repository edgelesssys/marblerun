package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/edgelesssys/coordinator/marble/cmd/common"
	"github.com/edgelesssys/coordinator/marble/marble"
)

func main() {
	configPath := flag.String("c", "", "config file path")
	flag.Parse()
	cfg := struct {
		CoordinatorAddr string
		MarbleType      string
		DNSNames        string
		DataPath        string
	}{
		"localhost:25554",
		"localhost:25555",
		"marble",
		"/tmp/edg_marble_0",
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

	// set env vars
	if err := os.Setenv(marble.EdgCoordinatorAddr, cfg.CoordinatorAddr); err != nil {
		log.Fatalf("failed to set env variable: %v", err)
		panic(err)
	}
	if err := os.Setenv(marble.EdgMarbleType, cfg.MarbleType); err != nil {
		log.Fatalf("failed to set env variable: %v", err)
		panic(err)
	}

	if err := os.Setenv(marble.EdgMarbleDNSNames, cfg.DNSNames); err != nil {
		log.Fatalf("failed to set env variable: %v", err)
		panic(err)
	}
	uuidFile := filepath.Join(cfg.DataPath, "uuid")
	if err := os.Setenv(marble.EdgMarbleUUIDFile, uuidFile); err != nil {
		log.Fatalf("failed to set env variable: %v", err)
		panic(err)
	}

	// call PreMain
	if err := marble.PreMainMock(); err != nil {
		panic(err)
	}
	ret := common.PremainTarget(len(os.Args), os.Args, os.Environ())
	if ret != 0 {
		panic(fmt.Errorf("premainTarget returned: %v", ret))
	}
	log.Println("Successfully authenticated with Coordinator!")
}
