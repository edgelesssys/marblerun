package coordinator

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/server"
	"github.com/stretchr/testify/assert"
)

// TODO: Use correct values here
const manifestJSON string = `{
	"Packages": {
		"backend": {
			"Debug": true,
			"SecurityVersion": 1,
			"ProductID": [3]
		}
	},
	"Infrastructures": {
		"Azure": {
			"QESVN": 2,
			"PCESVN": 3,
			"CPUSVN": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
			"RootCA": [3,3,3]
		}
	},
	"Marbles": {
		"test_marble": {
			"Package": "backend",
			"Parameters": {
				"Files": {
					"/abc/defg.txt": [7,7,7],
					"/ghi/jkl.mno": [8,8,8]
				},
				"Argv": [
					"serve"
				]
			}
		}
	},
	"Clients": {
		"owner": [9,9,9]
	}
}`

var coordinatorExe = flag.String("c", "", "Coordinator executable")
var marbleExe = flag.String("m", "", "Marble executable")
var marbleServerAddr, clientServerAddr string

func TestMain(m *testing.M) {
	flag.Parse()
	if *coordinatorExe == "" {
		log.Fatalln("You must provide the path of the coordinator executable using th -c flag.")
	}

	if *marbleExe == "" {
		log.Fatalln("You must provide the path of the marble executable using th -m flag.")
	}

	if _, err := os.Stat(*coordinatorExe); err != nil {
		log.Fatalln(err)
	}
	if _, err := os.Stat(*marbleExe); err != nil {
		log.Fatalln(err)
	}

	// get unused ports
	var listenerAPI, listenerDB net.Listener
	listenerAPI, marbleServerAddr = getListenerAndAddr()
	listenerDB, clientServerAddr = getListenerAndAddr()
	listenerAPI.Close()
	listenerDB.Close()
	log.Printf("Got marbleServerAddr: %v and clientServerAddr: %v\n", marbleServerAddr, clientServerAddr)
	os.Exit(m.Run())
}

func getListenerAndAddr() (net.Listener, string) {
	const localhost = "localhost:"

	listener, err := net.Listen("tcp", localhost)
	if err != nil {
		panic(err)
	}

	addr := listener.Addr().String()

	// addr contains IP address, we want hostname
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	return listener, localhost + port
}

// sanity test of the integration test environment
func TestTest(t *testing.T) {
	assert := assert.New(t)
	cfgFilename := createCoordinatorConfig()
	defer cleanupCoordinatorConfig(cfgFilename)
	assert.Nil(startCoordinator(cfgFilename).Kill())

	marbleCfg := createMarbleConfig(marbleServerAddr, clientServerAddr)
	assert.Nil(startMarble(marbleCfg).Kill())
}

func TestMarbleAPI(t *testing.T) {
	assert := assert.New(t)

	// start Coordinator
	cfgFilename := createCoordinatorConfig()
	defer cleanupCoordinatorConfig(cfgFilename)
	coordinatorProc := startCoordinator(cfgFilename)
	assert.NotNil(coordinatorProc)
	defer coordinatorProc.Kill()

	// set Manifest
	time.Sleep(time.Second * 5)
	var manifest core.Manifest
	err := json.Unmarshal([]byte(manifestJSON), &manifest)
	if err != nil {
		panic(err)
	}
	err = setManifest(manifest)
	assert.Nil(err, "failed to set Manifest: %v", err)

	// wait for me
	// log.Printf("coordinator Addr: %v", marbleServerAddr)
	// time.Sleep(100 * time.Second)

	// start Marble
	marbleCfg := createMarbleConfig(marbleServerAddr, "test_marble")
	marbleProc := startMarble(marbleCfg)
	assert.NotNil(marbleProc)
	defer marbleProc.Kill()

	// Check that Marble Authenticated successfully
	procState, err := marbleProc.Wait()
	assert.Nil(err, "error while waiting for marble proc: %v", err)
	assert.NotNil(procState, "procState is empty after call to Wait()")
	exitCode := procState.ExitCode()
	assert.Equal(0, exitCode, "marble authentication failed. exit code: %v", exitCode)
}

func TestClientAPI(t *testing.T) {
	// TODO
}

type coordinatorConfig struct {
	MeshServerAddr   string
	ClientServerAddr string
}

func createCoordinatorConfig() string {
	cfg := coordinatorConfig{MeshServerAddr: marbleServerAddr, ClientServerAddr: clientServerAddr}

	jsonCfg, err := json.Marshal(cfg)
	if err != nil {
		panic(err)
	}

	file, err := ioutil.TempFile("", "")
	if err != nil {
		panic(err)
	}

	name := file.Name()

	_, err = file.Write(jsonCfg)
	file.Close()
	if err != nil {
		os.Remove(name)
		panic(err)
	}

	return name
}

func cleanupCoordinatorConfig(filename string) {
	err := os.Remove(filename)
	if err != nil {
		panic(err)
	}
}

func startCoordinator(configFilename string) *os.Process {
	cmd := exec.Command(*coordinatorExe, "-c", configFilename)
	if err := cmd.Start(); err != nil {
		panic(err)
	}

	// Wait on the command so that cmd.ProcessState will be updated if the process dies.
	go cmd.Wait()

	log.Println("Coordinator starting ...")
	for {
		time.Sleep(100 * time.Millisecond)
		return cmd.Process
	}
}

func setManifest(manifest core.Manifest) error {
	// Use ClientAPI to set Manifest
	clientAPIURL := url.URL{
		Scheme: "http",
		Host:   clientServerAddr,
		Path:   "set_manifest", // TODO set real path
	}

	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		panic(err)
	}
	manifestReq := server.SetManifestRequest{
		Manifest: manifestRaw,
	}
	manifestReqRaw, err := json.Marshal(manifestReq)
	if err != nil {
		panic(err)
	}

	resp, err := http.Post(clientAPIURL.String(), "application/json", bytes.NewBuffer(manifestReqRaw))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("expected 200, but set_manifest returned %v: %v", resp.Status, string(body))
	}
	return nil
}

type marbleConfig struct {
	edgCoordinatorAddr string
	edgMarbleType      string
}

func createMarbleConfig(coordinatorAddr string, marbleType string) marbleConfig {
	cfg := marbleConfig{
		edgCoordinatorAddr: coordinatorAddr,
		edgMarbleType:      marbleType,
	}
	return cfg
}

func startMarble(config marbleConfig) *os.Process {
	if err := os.Setenv("EDG_COORDINATOR_ADDR", config.edgCoordinatorAddr); err != nil {
		panic(err)
	}
	if err := os.Setenv("EDG_MARBLE_TYPE", config.edgMarbleType); err != nil {
		panic(err)
	}
	cmd := exec.Command(*marbleExe)
	if err := cmd.Start(); err != nil {
		panic(err)
	}

	// Wait on the command so that cmd.ProcessState will be updated if the process dies.
	go cmd.Wait()

	log.Println("Marble starting ...")
	for {
		time.Sleep(10 * time.Millisecond)
		return cmd.Process
	}
}
