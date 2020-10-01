package test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/edgelesssys/coordinator/coordinator/config"
	"github.com/edgelesssys/coordinator/coordinator/core"
	mConfig "github.com/edgelesssys/coordinator/marble/config"
	"github.com/stretchr/testify/assert"
)

var coordinatorExe = flag.String("c", "", "Coordinator executable")
var marbleExe = flag.String("m", "", "Marble executable")
var simulationMode = flag.Bool("s", false, "Execute test in simulation mode (without real quoting)")
var marbleServerAddr, clientServerAddr string
var manifest core.Manifest

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

	if err := json.Unmarshal([]byte(IntegrationManifestJSON), &manifest); err != nil {
		log.Fatalln(err)
	}

	// get unused ports
	var listenerMarbleAPI, listenerClientAPI net.Listener
	listenerMarbleAPI, marbleServerAddr = getListenerAndAddr()
	listenerClientAPI, clientServerAddr = getListenerAndAddr()
	listenerMarbleAPI.Close()
	listenerClientAPI.Close()
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

	cfgFilename := createCoordinatorConfig("localhost")
	defer cleanupCoordinatorConfig(cfgFilename)
	assert.Nil(startCoordinator(cfgFilename).Kill())

	marbleCfg := createMarbleConfig(marbleServerAddr, "test_marble_client", "localhost")
	defer cleanupMarbleConfig(marbleCfg)
	assert.Nil(startMarble(marbleCfg).Process.Kill())
}

func TestMarbleAPI(t *testing.T) {
	assert := assert.New(t)

	// start Coordinator
	log.Println("Starting a coordinator enclave")
	cfgFilename := createCoordinatorConfig("localhost")
	defer cleanupCoordinatorConfig(cfgFilename)
	coordinatorProc := startCoordinator(cfgFilename)
	assert.NotNil(coordinatorProc)
	defer coordinatorProc.Kill()

	// set Manifest
	log.Println("Setting the Manifest")
	err := setManifest(manifest)
	assert.Nil(err, "failed to set Manifest: %v", err)

	// wait for me
	// marbleCfg := createMarbleConfig(marbleServerAddr, "test_marble_server", "test_marble_server")
	// log.Printf("config; %v", marbleCfg)
	// log.Printf("coordinator Addr: %v", marbleServerAddr)
	// time.Sleep(10000000 * time.Second)

	// start server
	log.Println("Starting a Server-Marble")
	serverCfg := createMarbleConfig(marbleServerAddr, "test_marble_server", "server,backend,localhost")
	defer cleanupMarbleConfig(serverCfg)
	serverCmd := runMarble(assert, serverCfg, true, false)
	defer serverCmd.Process.Kill()
	err = waitForServer()
	// start clients
	log.Println("Starting a bunch of Client-Marbles")
	assert.Nil(err, "failed to start server-marble: %v", err)
	clientCfg := createMarbleConfig(marbleServerAddr, "test_marble_client", "client,frontend,localhost")
	defer cleanupMarbleConfig(clientCfg)
	_ = runMarble(assert, clientCfg, true, true)
	_ = runMarble(assert, clientCfg, true, true)
	if !*simulationMode {
		// start bad marbles (would be accepted if we run in SimulationMode)
		badCfg := createMarbleConfig(marbleServerAddr, "bad_marble", "bad,localhost")
		defer cleanupMarbleConfig(badCfg)
		_ = runMarble(assert, badCfg, false, true)
		_ = runMarble(assert, badCfg, false, true)
	}
}

func TestRestart(t *testing.T) {
	assert := assert.New(t)
	log.Println("Testing the restart capabilities")
	// start Coordinator
	log.Println("Starting a coordinator enclave")
	cfgFilename := createCoordinatorConfig("localhost")
	defer cleanupCoordinatorConfig(cfgFilename)
	coordinatorProc := startCoordinator(cfgFilename)
	assert.NotNil(coordinatorProc)
	// set Manifest
	log.Println("Setting the Manifest")
	err := setManifest(manifest)
	assert.Nil(err, "failed to set Manifest: %v", err)
	// start server
	log.Println("Starting a Server-Marble")
	serverCfg := createMarbleConfig(marbleServerAddr, "test_marble_server", "server,backend,localhost")
	defer cleanupMarbleConfig(serverCfg)
	serverCmd := runMarble(assert, serverCfg, true, false)
	defer serverCmd.Process.Kill()
	err = waitForServer()
	// start clients
	log.Println("Starting a bunch of Client-Marbles")
	assert.Nil(err, "failed to start server-marble: %v", err)
	clientCfg := createMarbleConfig(marbleServerAddr, "test_marble_client", "client,frontend,localhost")
	defer cleanupMarbleConfig(clientCfg)
	_ = runMarble(assert, clientCfg, true, true)
	_ = runMarble(assert, clientCfg, true, true)

	// simulate restart of coordinator
	log.Println("Simulating a restart of the coordinator enclave...")
	log.Println("Killing the old instance")
	if err := coordinatorProc.Kill(); err != nil {
		panic(err)
	}
	log.Println("Restarting the old instance")
	coordinatorProc = startCoordinator(cfgFilename)
	assert.NotNil(coordinatorProc)
	defer coordinatorProc.Kill()

	// try do malicious update of manifest
	log.Println("Trying to set a new Manifest, which should already be set")
	err = setManifest(manifest)
	assert.NotNil(err, "expected updating of manifest to fail, but succeeded")

	// start a bunch of client marbles and assert they still work with old server marble
	log.Println("Starting a bunch of Client-Marbles, which should still authenticate successfully with the Server-Marble")
	_ = runMarble(assert, clientCfg, true, true)
	_ = runMarble(assert, clientCfg, true, true)
}

func runMarble(assert *assert.Assertions, marbleCfg marbleConfig, shouldSucceed bool, terminates bool) *exec.Cmd {
	log.Println("Starting marble")
	marbleCmd := startMarble(marbleCfg)
	assert.NotNil(marbleCmd)

	if !terminates {
		return marbleCmd
	}

	// Check that Marble Authenticated successfully
	err := marbleCmd.Wait()
	if !shouldSucceed {
		assert.NotNil(err, "expected Wait to fail because of return value != 0, but got not error")
		assert.NotNil(marbleCmd.ProcessState)
		exitCode := marbleCmd.ProcessState.ExitCode()
		assert.NotEqual(0, exitCode, "expected marble authentication to fail, but got exit code: %v", exitCode)
		return marbleCmd
	}
	assert.Nil(err, "error while waiting for marble process: %v", err)
	assert.NotNil(marbleCmd.ProcessState, "empty ProcessState after Wait")
	exitCode := marbleCmd.ProcessState.ExitCode()
	assert.Equal(0, exitCode, "marble authentication failed. exit code: %v", exitCode)
	if exitCode == 0 {
		log.Println("Marble authenticated successfully and terminated.")
	}
	return marbleCmd
}

func waitForServer() error {
	log.Println("Waiting for server...")
	timeout := time.Second * 5
	var err error
	for i := 0; i < 20; i++ {
		var conn net.Conn
		conn, err = net.DialTimeout("tcp", net.JoinHostPort("localhost", "8080"), timeout)
		if err == nil {
			conn.Close()
			log.Println("Server started")
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("connection error: %v", err)
}

func TestClientAPI(t *testing.T) {
	assert := assert.New(t)
	eof := errors.New("EOF")

	// start Coordinator
	cfgFilename := createCoordinatorConfig("localhost")
	defer cleanupCoordinatorConfig(cfgFilename)
	coordinatorProc := startCoordinator(cfgFilename)
	assert.NotNil(coordinatorProc, "could not start coordinator")
	defer coordinatorProc.Kill()

	//create client
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := http.Client{Transport: tr}
	clientAPIURL := url.URL{
		Scheme: "https",
		Host:   clientServerAddr,
		Path:   "quote",
	}

	//test get quote
	resp, err := client.Get(clientAPIURL.String())
	assert.Nil(err, err)
	assert.Equal(http.StatusOK, resp.StatusCode, "get quote failed")
	resp.Body.Close()

	//test manifest
	clientAPIURL.Path = "manifest"

	//try read before set
	buffer := make([]byte, 1024)
	resp, err = client.Get(clientAPIURL.String())
	_, readErr := resp.Body.Read(buffer)

	assert.Nil(err, err)
	assert.Equal(eof, readErr)
	assert.Contains(string(buffer), "{\"ManifestSignature\":null}")
	assert.Equal(http.StatusOK, resp.StatusCode, "status != ok")
	resp.Body.Close()

	//set Manifest
	resp, err = client.Post(clientAPIURL.String(), "application/json", bytes.NewBuffer([]byte(IntegrationManifestJSON)))

	assert.Nil(err)
	assert.Equal(http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	//read after set
	resp, err = client.Get(clientAPIURL.String())

	assert.Nil(err)
	assert.Equal(http.StatusOK, resp.StatusCode)

	_, readErr = resp.Body.Read(buffer)
	resp.Body.Close()

	assert.Equal(eof, readErr, readErr)
	assert.NotContains(string(buffer), "{\"ManifestSignature\":null}")

	//try set manifest again
	resp, err = client.Post(clientAPIURL.String(), "application/json", bytes.NewBuffer([]byte(IntegrationManifestJSON)))
	assert.Nil(err)
	assert.Equal(http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()

	//todo test status AB#121

}

type coordinatorConfig struct {
	MeshServerAddr   string
	ClientServerAddr string
	DNSNames         string
	SealDir          string
}

func createCoordinatorConfig(dnsNames string) coordinatorConfig {
	tempDir, err := ioutil.TempDir("/tmp", "edg_coordinator_*")
	if err != nil {
		panic(err)
	}
	cfg := coordinatorConfig{MeshServerAddr: marbleServerAddr, ClientServerAddr: clientServerAddr, DNSNames: dnsNames, SealDir: tempDir}

	return cfg
}

func cleanupCoordinatorConfig(cfg coordinatorConfig) {
	if err := os.RemoveAll(cfg.SealDir); err != nil {
		panic(err)
	}
}

func makeEnv(key, value string) string {
	return fmt.Sprintf("%v=%v", key, value)
}

func startCoordinator(cfg coordinatorConfig) *os.Process {
	var cmd *exec.Cmd
	if *simulationMode {
		cmd = exec.Command(*coordinatorExe)
	} else {
		cmd = exec.Command("erthost", *coordinatorExe)
	}
	cmd.Env = []string{
		makeEnv(config.EdgMeshServerAddr, cfg.MeshServerAddr),
		makeEnv(config.EdgClientServerAddr, cfg.ClientServerAddr),
		makeEnv(config.EdgCoordinatorDNSNames, cfg.DNSNames),
		makeEnv(config.EdgCoordinatorSealDir, cfg.SealDir),
	}
	output := make(chan []byte)
	go func() {
		out, _ := cmd.CombinedOutput()
		output <- out
	}()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{Transport: tr}
	url := url.URL{Scheme: "https", Host: clientServerAddr, Path: "quote"}

	log.Println("Coordinator starting ...")
	for {
		time.Sleep(10 * time.Millisecond)
		select {
		case out := <-output:
			// process died
			log.Println(string(out))
			return nil
		default:
		}
		resp, err := client.Get(url.String())
		if err == nil {
			log.Println("Coordinator started")
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				panic(resp.Status)
			}
			return cmd.Process
		}
	}
}

func setManifest(manifest core.Manifest) error {
	// Use ClientAPI to set Manifest
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{Transport: tr}
	clientAPIURL := url.URL{
		Scheme: "https",
		Host:   clientServerAddr,
		Path:   "manifest",
	}

	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		panic(err)
	}

	resp, err := client.Post(clientAPIURL.String(), "application/json", bytes.NewBuffer([]byte(manifestRaw)))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected %v, but /manifest returned %v: %v", http.StatusOK, resp.Status, string(body))
	}
	return nil
}

type marbleConfig struct {
	CoordinatorAddr string
	MarbleType      string
	DNSNames        string
	DataPath        string
}

func createMarbleConfig(coordinatorAddr, marbleType, marbleDNSNames string) marbleConfig {
	cfg := marbleConfig{
		CoordinatorAddr: coordinatorAddr,
		MarbleType:      marbleType,
		DNSNames:        marbleDNSNames,
	}
	var err error
	cfg.DataPath, err = ioutil.TempDir("", "")
	if err != nil {
		panic(err)
	}
	return cfg
}

func cleanupMarbleConfig(cfg marbleConfig) {
	if err := os.RemoveAll(cfg.DataPath); err != nil {
		panic(err)
	}
}

func startMarble(cfg marbleConfig) *exec.Cmd {
	var cmd *exec.Cmd
	if *simulationMode {
		cmd = exec.Command(*marbleExe)
	} else {
		cmd = exec.Command("erthost", *marbleExe)
	}
	uuidFile := filepath.Join(cfg.DataPath, "uuid")
	cmd.Env = []string{
		makeEnv(mConfig.EdgCoordinatorAddr, cfg.CoordinatorAddr),
		makeEnv(mConfig.EdgMarbleType, cfg.MarbleType),
		makeEnv(mConfig.EdgMarbleDNSNames, cfg.DNSNames),
		makeEnv(mConfig.EdgMarbleUUIDFile, uuidFile),
	}
	if err := cmd.Start(); err != nil {
		panic(err)
	}

	log.Println("Marble started")
	return cmd
}
