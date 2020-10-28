// +build integration

package test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
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
	"path/filepath"
	"testing"
	"time"

	"github.com/edgelesssys/coordinator/coordinator/config"
	"github.com/edgelesssys/coordinator/coordinator/core"
	mConfig "github.com/edgelesssys/coordinator/marble/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

var coordinatorDir = flag.String("c", "", "Coordinator build dir")
var marbleDir = flag.String("m", "", "Marble build dir")
var simulationMode = flag.Bool("s", false, "Execute test in simulation mode (without real quoting)")
var noenclave = flag.Bool("noenclave", false, "Do not run with erthost")
var meshServerAddr, clientServerAddr string
var manifest core.Manifest
var transportSkipVerify = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

func TestMain(m *testing.M) {
	flag.Parse()
	if *coordinatorDir == "" {
		log.Fatalln("You must provide the path of the coordinator executable using th -c flag.")
	}

	if *marbleDir == "" {
		log.Fatalln("You must provide the path of the marble executable using th -m flag.")
	}

	if _, err := os.Stat(*coordinatorDir); err != nil {
		log.Fatalln(err)
	}
	if _, err := os.Stat(*marbleDir); err != nil {
		log.Fatalln(err)
	}

	if err := json.Unmarshal([]byte(IntegrationManifestJSON), &manifest); err != nil {
		log.Fatalln(err)
	}
	updateManifest()

	// get unused ports
	var listenerMeshAPI, listenerClientAPI net.Listener
	listenerMeshAPI, meshServerAddr = getListenerAndAddr()
	listenerClientAPI, clientServerAddr = getListenerAndAddr()
	listenerMeshAPI.Close()
	listenerClientAPI.Close()
	log.Printf("Got meshServerAddr: %v and clientServerAddr: %v\n", meshServerAddr, clientServerAddr)
	os.Exit(m.Run())
}

func updateManifest() {
	config, err := ioutil.ReadFile(filepath.Join(*marbleDir, "config.json"))
	if err != nil {
		panic(err)
	}
	var cfg struct {
		SecurityVersion uint
		UniqueID        string
		SignerID        string
		ProductID       uint16
	}
	if err := json.Unmarshal(config, &cfg); err != nil {
		panic(err)
	}

	pkg := manifest.Packages["backend"]
	pkg.UniqueID = cfg.UniqueID
	pkg.SignerID = cfg.SignerID
	pkg.SecurityVersion = &cfg.SecurityVersion
	pkg.ProductID = make([]byte, 2)
	binary.LittleEndian.PutUint16(pkg.ProductID, cfg.ProductID)
	manifest.Packages["backend"] = pkg
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

	cfg := newCoordinatorConfig()
	defer cfg.cleanup()
	assert.Nil(startCoordinator(cfg).Kill())

	marbleCfg := newMarbleConfig(meshServerAddr, "test_marble_client", "localhost")
	defer marbleCfg.cleanup()
	assert.Nil(startMarble(marbleCfg).Process.Kill())
}

func TestMarbleAPI(t *testing.T) {
	assert := assert.New(t)

	// start Coordinator
	log.Println("Starting a coordinator enclave")
	cfg := newCoordinatorConfig()
	defer cfg.cleanup()
	coordinatorProc := startCoordinator(cfg)
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
	serverCfg := newMarbleConfig(meshServerAddr, "test_marble_server", "server,backend,localhost")
	defer serverCfg.cleanup()
	serverCmd := runMarble(assert, serverCfg, true, false)
	defer serverCmd.Process.Kill()
	err = waitForServer()
	// start clients
	log.Println("Starting a bunch of Client-Marbles")
	assert.Nil(err, "failed to start server-marble: %v", err)
	clientCfg := newMarbleConfig(meshServerAddr, "test_marble_client", "client,frontend,localhost")
	defer clientCfg.cleanup()
	_ = runMarble(assert, clientCfg, true, true)
	_ = runMarble(assert, clientCfg, true, true)
	if !*simulationMode {
		// start bad marbles (would be accepted if we run in SimulationMode)
		badCfg := newMarbleConfig(meshServerAddr, "bad_marble", "bad,localhost")
		defer badCfg.cleanup()
		_ = runMarble(assert, badCfg, false, true)
		_ = runMarble(assert, badCfg, false, true)
	}
}

func TestRestart(t *testing.T) {
	assert := assert.New(t)
	log.Println("Testing the restart capabilities")
	// start Coordinator
	log.Println("Starting a coordinator enclave")
	cfg := newCoordinatorConfig()
	defer cfg.cleanup()
	coordinatorProc := startCoordinator(cfg)
	assert.NotNil(coordinatorProc)
	// set Manifest
	log.Println("Setting the Manifest")
	err := setManifest(manifest)
	assert.Nil(err, "failed to set Manifest: %v", err)
	// start server
	log.Println("Starting a Server-Marble")
	serverCfg := newMarbleConfig(meshServerAddr, "test_marble_server", "server,backend,localhost")
	defer serverCfg.cleanup()
	serverCmd := runMarble(assert, serverCfg, true, false)
	defer serverCmd.Process.Kill()
	err = waitForServer()
	// start clients
	log.Println("Starting a bunch of Client-Marbles")
	assert.Nil(err, "failed to start server-marble: %v", err)
	clientCfg := newMarbleConfig(meshServerAddr, "test_marble_client", "client,frontend,localhost")
	defer clientCfg.cleanup()
	_ = runMarble(assert, clientCfg, true, true)
	_ = runMarble(assert, clientCfg, true, true)

	// simulate restart of coordinator
	log.Println("Simulating a restart of the coordinator enclave...")
	log.Println("Killing the old instance")
	if err := coordinatorProc.Kill(); err != nil {
		panic(err)
	}
	log.Println("Restarting the old instance")
	coordinatorProc = startCoordinator(cfg)
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
	require := require.New(t)

	// start Coordinator
	cfg := newCoordinatorConfig()
	defer cfg.cleanup()
	coordinatorProc := startCoordinator(cfg)
	require.NotNil(coordinatorProc, "could not start coordinator")
	defer coordinatorProc.Kill()

	// get certificate
	client := http.Client{Transport: transportSkipVerify}
	clientAPIURL := url.URL{Scheme: "https", Host: clientServerAddr, Path: "quote"}
	resp, err := client.Get(clientAPIURL.String())
	require.NoError(err)
	require.Equal(http.StatusOK, resp.StatusCode)
	quote, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(err)
	cert := gjson.Get(string(quote), "Cert").String()
	require.NotEmpty(cert)

	// test with certificate
	pool := x509.NewCertPool()
	require.True(pool.AppendCertsFromPEM([]byte(cert)))
	client = http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	clientAPIURL.Path = "manifest"
	resp, err = client.Get(clientAPIURL.String())
	require.NoError(err)
	require.Equal(http.StatusOK, resp.StatusCode)
	manifest, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(err)
	assert.JSONEq(`{"ManifestSignature":""}`, string(manifest))
}

type coordinatorConfig struct {
	dnsNames string
	sealDir  string
}

func newCoordinatorConfig() coordinatorConfig {
	sealDir, err := ioutil.TempDir("", "")
	if err != nil {
		panic(err)
	}
	return coordinatorConfig{dnsNames: "localhost", sealDir: sealDir}
}

func (c coordinatorConfig) cleanup() {
	if err := os.RemoveAll(c.sealDir); err != nil {
		panic(err)
	}
}

func makeEnv(key, value string) string {
	return fmt.Sprintf("%v=%v", key, value)
}

func startCoordinator(cfg coordinatorConfig) *os.Process {
	var cmd *exec.Cmd
	if *noenclave {
		cmd = exec.Command(filepath.Join(*coordinatorDir, "coordinator-noenclave"))
	} else {
		cmd = exec.Command("erthost", filepath.Join(*coordinatorDir, "enclave.signed"))
	}
	var simFlag string
	if *simulationMode {
		simFlag = makeEnv("OE_SIMULATION", "1")
	} else {
		simFlag = makeEnv("OE_SIMULATION", "0")
	}
	cmd.Env = []string{
		makeEnv(config.MeshAddr, meshServerAddr),
		makeEnv(config.ClientAddr, clientServerAddr),
		makeEnv(config.DNSNames, cfg.dnsNames),
		makeEnv(config.SealDir, cfg.sealDir),
		simFlag,
	}
	output := make(chan []byte)
	go func() {
		out, _ := cmd.CombinedOutput()
		output <- out
	}()

	client := http.Client{Transport: transportSkipVerify}
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
	client := http.Client{Transport: transportSkipVerify}
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
	coordinatorAddr string
	marbleType      string
	dnsNames        string
	dataDir         string
}

func newMarbleConfig(coordinatorAddr, marbleType, dnsNames string) marbleConfig {
	dataDir, err := ioutil.TempDir("", "")
	if err != nil {
		panic(err)
	}
	return marbleConfig{
		coordinatorAddr: coordinatorAddr,
		marbleType:      marbleType,
		dnsNames:        dnsNames,
		dataDir:         dataDir,
	}
}

func (c marbleConfig) cleanup() {
	if err := os.RemoveAll(c.dataDir); err != nil {
		panic(err)
	}
}

func startMarble(cfg marbleConfig) *exec.Cmd {
	var cmd *exec.Cmd
	if *noenclave {
		cmd = exec.Command(filepath.Join(*marbleDir, "marble-test-noenclave"))
	} else {
		cmd = exec.Command("erthost", filepath.Join(*marbleDir, "enclave.signed"))
	}
	var simFlag string
	if *simulationMode {
		simFlag = makeEnv("OE_SIMULATION", "1")
	} else {
		simFlag = makeEnv("OE_SIMULATION", "0")
	}
	uuidFile := filepath.Join(cfg.dataDir, "uuid")
	cmd.Env = []string{
		makeEnv(mConfig.CoordinatorAddr, cfg.coordinatorAddr),
		makeEnv(mConfig.Type, cfg.marbleType),
		makeEnv(mConfig.DNSNames, cfg.dnsNames),
		makeEnv(mConfig.UUIDFile, uuidFile),
		simFlag,
	}
	if err := cmd.Start(); err != nil {
		panic(err)
	}

	log.Println("Marble started")
	return cmd
}
