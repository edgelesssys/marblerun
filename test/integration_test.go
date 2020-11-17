// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// +build integration

package test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

	"github.com/edgelesssys/marblerun/coordinator/config"
	"github.com/edgelesssys/marblerun/coordinator/core"
	"github.com/edgelesssys/marblerun/coordinator/server"
	mconfig "github.com/edgelesssys/marblerun/marble/config"
	"github.com/edgelesssys/marblerun/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

var buildDir = flag.String("b", "", "build dir")
var simulationMode = flag.Bool("s", false, "Execute test in simulation mode (without real quoting)")
var noenclave = flag.Bool("noenclave", false, "Do not run with erthost")
var meshServerAddr, clientServerAddr, marbleTestAddr string
var manifest core.Manifest
var transportSkipVerify = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
var simFlag string

func TestMain(m *testing.M) {
	flag.Parse()
	if *buildDir == "" {
		log.Fatalln("You must provide the path of the build directory using th -b flag.")
	}
	if _, err := os.Stat(*buildDir); err != nil {
		log.Fatalln(err)
	}

	if *simulationMode {
		simFlag = makeEnv("OE_SIMULATION", "1")
	} else {
		simFlag = makeEnv("OE_SIMULATION", "0")
	}

	if err := json.Unmarshal([]byte(IntegrationManifestJSON), &manifest); err != nil {
		log.Fatalln(err)
	}
	updateManifest()

	// get unused ports
	var listenerMeshAPI, listenerClientAPI, listenerTestMarble net.Listener
	listenerMeshAPI, meshServerAddr = util.MustGetLocalListenerAndAddr()
	listenerClientAPI, clientServerAddr = util.MustGetLocalListenerAndAddr()
	listenerTestMarble, marbleTestAddr = util.MustGetLocalListenerAndAddr()
	listenerMeshAPI.Close()
	listenerClientAPI.Close()
	listenerTestMarble.Close()
	log.Printf("Got meshServerAddr: %v and clientServerAddr: %v\n", meshServerAddr, clientServerAddr)

	os.Exit(m.Run())
}

func updateManifest() {
	config, err := ioutil.ReadFile(filepath.Join(*buildDir, "marble-test-config.json"))
	if err != nil {
		panic(err)
	}
	var cfg struct {
		SecurityVersion uint
		UniqueID        string
		SignerID        string
		ProductID       uint64
	}
	if err := json.Unmarshal(config, &cfg); err != nil {
		panic(err)
	}

	pkg := manifest.Packages["backend"]
	pkg.UniqueID = cfg.UniqueID
	pkg.SignerID = cfg.SignerID
	pkg.SecurityVersion = &cfg.SecurityVersion
	pkg.ProductID = &cfg.ProductID
	manifest.Packages["backend"] = pkg
}

// sanity test of the integration test environment
func TestTest(t *testing.T) {
	assert := assert.New(t)

	cfg := newCoordinatorConfig()
	defer cfg.cleanup()
	assert.Nil(startCoordinator(cfg).Kill())

	marbleCfg := newMarbleConfig(meshServerAddr, "test_marble_client", "localhost")
	defer marbleCfg.cleanup()
	assert.False(startMarbleClient(marbleCfg))
}

func TestMarbleAPI(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// start Coordinator
	log.Println("Starting a coordinator enclave")
	cfg := newCoordinatorConfig()
	defer cfg.cleanup()
	coordinatorProc := startCoordinator(cfg)
	require.NotNil(coordinatorProc)
	defer coordinatorProc.Kill()

	// set Manifest
	log.Println("Setting the Manifest")
	_, err := setManifest(manifest)
	require.NoError(err, "failed to set Manifest")

	// start server
	log.Println("Starting a Server-Marble")
	serverCfg := newMarbleConfig(meshServerAddr, "test_marble_server", "server,backend,localhost")
	defer serverCfg.cleanup()
	serverProc := startMarbleServer(serverCfg)
	require.NotNil(serverProc, "failed to start server-marble")
	defer serverProc.Kill()

	// start clients
	log.Println("Starting a bunch of Client-Marbles")
	clientCfg := newMarbleConfig(meshServerAddr, "test_marble_client", "client,frontend,localhost")
	defer clientCfg.cleanup()
	assert.True(startMarbleClient(clientCfg))
	assert.True(startMarbleClient(clientCfg))
	if !*simulationMode && !*noenclave {
		// start bad marbles (would be accepted if we run in SimulationMode)
		badCfg := newMarbleConfig(meshServerAddr, "bad_marble", "bad,localhost")
		defer badCfg.cleanup()
		assert.False(startMarbleClient(badCfg))
		assert.False(startMarbleClient(badCfg))
	}
}

func TestRestart(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	log.Println("Testing the restart capabilities")
	// start Coordinator
	log.Println("Starting a coordinator enclave")
	cfg := newCoordinatorConfig()
	defer cfg.cleanup()
	coordinatorProc := startCoordinator(cfg)
	require.NotNil(coordinatorProc)

	// set Manifest
	_, err := setManifest(manifest)
	require.NoError(err, "failed to set Manifest")

	// start server
	log.Println("Starting a Server-Marble")
	serverCfg := newMarbleConfig(meshServerAddr, "test_marble_server", "server,backend,localhost")
	defer serverCfg.cleanup()
	serverProc := startMarbleServer(serverCfg)
	require.NotNil(serverProc, "failed to start server-marble")
	defer serverProc.Kill()

	// start clients
	log.Println("Starting a bunch of Client-Marbles")
	clientCfg := newMarbleConfig(meshServerAddr, "test_marble_client", "client,frontend,localhost")
	defer clientCfg.cleanup()
	assert.True(startMarbleClient(clientCfg))
	assert.True(startMarbleClient(clientCfg))

	// simulate restart of coordinator
	log.Println("Simulating a restart of the coordinator enclave...")
	log.Println("Killing the old instance")
	require.NoError(coordinatorProc.Kill())
	log.Println("Restarting the old instance")
	coordinatorProc = startCoordinator(cfg)
	require.NotNil(coordinatorProc)
	defer coordinatorProc.Kill()

	// try do malicious update of manifest
	log.Println("Trying to set a new Manifest, which should already be set")
	_, err = setManifest(manifest)
	assert.Error(err, "expected updating of manifest to fail, but succeeded")

	// start a bunch of client marbles and assert they still work with old server marble
	log.Println("Starting a bunch of Client-Marbles, which should still authenticate successfully with the Server-Marble")
	assert.True(startMarbleClient(clientCfg))
	assert.True(startMarbleClient(clientCfg))
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

func TestRecoveryRestoreKey(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	log.Println("Testing recovery...")

	// start Coordinator
	log.Println("Starting a coordinator enclave")
	cfg := newCoordinatorConfig()
	defer cfg.cleanup()
	coordinatorProc := startCoordinator(cfg)
	require.NotNil(coordinatorProc)

	// set Manifest
	log.Println("Setting the Manifest")
	recoveryResponse, err := setManifest(manifest)
	require.NoError(err, "failed to set Manifest")

	// start server
	log.Println("Starting a Server-Marble")
	serverCfg := newMarbleConfig(meshServerAddr, "test_marble_server", "server,backend,localhost")
	defer serverCfg.cleanup()
	serverProc := startMarbleServer(serverCfg)
	require.NotNil(serverProc, "failed to start server-marble")
	defer serverProc.Kill()

	// simulate restart of coordinator
	log.Println("Simulating a restart of the coordinator enclave...")
	log.Println("Killing the old instance")
	require.NoError(coordinatorProc.Kill())

	// Garble encryption key to trigger recovery state
	log.Println("Garbeling sealed key...")
	pathToKeyFile := filepath.Join(cfg.sealDir, core.SealedKeyFname)
	sealedKeyData, err := ioutil.ReadFile(pathToKeyFile)
	require.NoError(err)
	sealedKeyData[0] = sealedKeyData[0] ^ byte(0x42)
	require.NoError(ioutil.WriteFile(pathToKeyFile, sealedKeyData, 0600))

	// Restart server, we should be in recovery mode
	log.Println("Restarting the old instance")
	coordinatorProc = startCoordinator(cfg)
	require.NotNil(coordinatorProc)
	defer coordinatorProc.Kill()

	// Query status API, check if status response begins with Code 1 (recovery state)
	log.Println("Checking status...")
	statusResponse, err := getStatus()
	require.NoError(err)
	assert.Contains(statusResponse, "{\"Code\":1,")

	// Decode & Decrypt recovery data from when we set the manifest
	var recoveryDataUnmarshalled server.RecoveryDataResp
	require.NoError(json.Unmarshal(recoveryResponse, &recoveryDataUnmarshalled), "Failed to unmarshal JSON response containing the recovery data.")
	recoveryDataEncrypted, err := base64.StdEncoding.DecodeString(recoveryDataUnmarshalled.EncryptionKey)
	require.NoError(err, "Failed to base64 decode recovery data.")
	recoveryKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, RecoveryPrivateKey, recoveryDataEncrypted, nil)
	require.NoError(err, "Failed to RSA OAEP decrypt the recovery data.")

	// Perform recovery
	require.NoError(setRecover(recoveryKey))
	log.Println("Performed recovery, now checking status again...")
	statusResponse, err = getStatus()
	require.NoError(err)
	assert.Contains(statusResponse, "{\"Code\":3,", "Server is in wrong status after recovery.")

	// Simulate restart of coordinator
	log.Println("Simulating a restart of the coordinator enclave...")
	log.Println("Killing the old instance")
	require.NoError(coordinatorProc.Kill())

	// Restart server, we should be in recovery mode
	log.Println("Restarting the old instance")
	coordinatorProc = startCoordinator(cfg)
	require.NotNil(coordinatorProc)
	defer coordinatorProc.Kill()

	// Finally, check if we survive a restart.
	log.Println("Restarted instance, now let's see if the state can be restored again successfully.")
	statusResponse, err = getStatus()
	require.NoError(err)
	assert.Contains(statusResponse, "{\"Code\":3,", "Server is in wrong status after recovery.")
}

func TestRecoveryReset(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	log.Println("Testing recovery...")

	// start Coordinator
	log.Println("Starting a coordinator enclave")
	cfg := newCoordinatorConfig()
	defer cfg.cleanup()
	coordinatorProc := startCoordinator(cfg)
	require.NotNil(coordinatorProc)

	// set Manifest
	log.Println("Setting the Manifest")
	_, err := setManifest(manifest)
	require.NoError(err, "failed to set Manifest")

	// start server
	log.Println("Starting a Server-Marble")
	serverCfg := newMarbleConfig(meshServerAddr, "test_marble_server", "server,backend,localhost")
	defer serverCfg.cleanup()
	serverProc := startMarbleServer(serverCfg)
	require.NotNil(serverProc, "failed to start server-marble")
	defer serverProc.Kill()

	// simulate restart of coordinator
	log.Println("Simulating a restart of the coordinator enclave...")
	log.Println("Killing the old instance")
	require.NoError(coordinatorProc.Kill())

	// Garble encryption key to trigger recovery state
	log.Println("Garbeling sealed key...")
	pathToKeyFile := filepath.Join(cfg.sealDir, core.SealedKeyFname)
	sealedKeyData, err := ioutil.ReadFile(pathToKeyFile)
	require.NoError(err)
	sealedKeyData[0] = sealedKeyData[0] ^ byte(0x42)
	require.NoError(ioutil.WriteFile(pathToKeyFile, sealedKeyData, 0600))

	// Restart server, we should be in recovery mode
	log.Println("Restarting the old instance")
	coordinatorProc = startCoordinator(cfg)
	require.NotNil(coordinatorProc)
	defer coordinatorProc.Kill()

	// Query status API, check if status response begins with Code 1 (recovery state)
	log.Println("Checking status...")
	statusResponse, err := getStatus()
	require.NoError(err)
	assert.Contains(statusResponse, "{\"Code\":1,")

	// Set manifest again
	log.Println("Setting the Manifest")
	_, err = setManifest(manifest)
	require.NoError(err, "failed to set Manifest")

	// Check status after setting a new manifest, we should be able
	log.Println("Check if the manifest was accepted and we are ready to accept Marbles")
	statusResponse, err = getStatus()
	require.NoError(err)
	assert.Contains(statusResponse, "{\"Code\":3,", "Server is in wrong status after recovery.")

	// simulate restart of coordinator
	log.Println("Simulating a restart of the coordinator enclave...")
	log.Println("Killing the old instance")
	require.NoError(coordinatorProc.Kill())

	// Restart server, we should be in recovery mode
	log.Println("Restarting the old instance")
	coordinatorProc = startCoordinator(cfg)
	require.NotNil(coordinatorProc)
	defer coordinatorProc.Kill()

	// Finally, check if we survive a restart.
	log.Println("Restarted instance, now let's see if the new state can be decrypted successfully...")
	statusResponse, err = getStatus()
	require.NoError(err)
	assert.Contains(statusResponse, "{\"Code\":3,", "Server is in wrong status after recovery.")
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
		cmd = exec.Command(filepath.Join(*buildDir, "coordinator-noenclave"))
	} else {
		cmd = exec.Command("erthost", filepath.Join(*buildDir, "coordinator-enclave.signed"))
	}
	cmd.Env = []string{
		makeEnv(config.MeshAddr, meshServerAddr),
		makeEnv(config.ClientAddr, clientServerAddr),
		makeEnv(config.DNSNames, cfg.dnsNames),
		makeEnv(config.SealDir, cfg.sealDir),
		simFlag,
	}
	output := startCommand(cmd)

	client := http.Client{Transport: transportSkipVerify}
	url := url.URL{Scheme: "https", Host: clientServerAddr, Path: "quote"}

	log.Println("Coordinator starting ...")
	for {
		time.Sleep(10 * time.Millisecond)
		select {
		case out := <-output:
			// process died
			log.Println(out)
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

func startCommand(cmd *exec.Cmd) chan string {
	output := make(chan string)
	go func() {
		out, err := cmd.CombinedOutput()
		if err != nil {
			if _, ok := err.(*exec.ExitError); !ok {
				output <- err.Error()
				return
			}
		}
		output <- string(out)
	}()
	return output
}

func setManifest(manifest core.Manifest) ([]byte, error) {
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

	resp, err := client.Post(clientAPIURL.String(), "application/json", bytes.NewReader(manifestRaw))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected %v, but /manifest returned %v: %v", http.StatusOK, resp.Status, string(body))
	}

	if err != nil {
		panic(err)
	}

	return body, nil
}

func setRecover(recoveryKey []byte) error {
	client := http.Client{Transport: transportSkipVerify}
	clientAPIURL := url.URL{
		Scheme: "https",
		Host:   clientServerAddr,
		Path:   "recover",
	}

	resp, err := client.Post(clientAPIURL.String(), "application/octet-stream", bytes.NewReader(recoveryKey))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected %v, but /recover returned %v: %v", http.StatusOK, resp.Status, string(body))
	}

	if err != nil {
		panic(err)
	}

	return nil
}

func getStatus() (string, error) {
	client := http.Client{Transport: transportSkipVerify}
	clientAPIURL := url.URL{
		Scheme: "https",
		Host:   clientServerAddr,
		Path:   "status",
	}

	resp, err := client.Get(clientAPIURL.String())
	if err != nil {
		panic(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("expected %v, but /status returned %v: %v", http.StatusOK, resp.Status, string(body))
	}

	if err != nil {
		panic(err)
	}

	return string(body), nil
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

func getMarbleCmd(cfg marbleConfig) *exec.Cmd {
	var cmd *exec.Cmd
	if *noenclave {
		cmd = exec.Command(filepath.Join(*buildDir, "marble-test-noenclave"))
	} else {
		cmd = exec.Command("erthost", filepath.Join(*buildDir, "marble-test-enclave.signed"))
	}
	uuidFile := filepath.Join(cfg.dataDir, "uuid")
	cmd.Env = []string{
		makeEnv(mconfig.CoordinatorAddr, cfg.coordinatorAddr),
		makeEnv(mconfig.Type, cfg.marbleType),
		makeEnv(mconfig.DNSNames, cfg.dnsNames),
		makeEnv(mconfig.UUIDFile, uuidFile),
		makeEnv("EDG_TEST_ADDR", marbleTestAddr),
		simFlag,
	}
	return cmd
}

func startMarbleServer(cfg marbleConfig) *os.Process {
	cmd := getMarbleCmd(cfg)
	output := startCommand(cmd)

	log.Println("Waiting for server...")
	timeout := time.Second * 5
	for {
		time.Sleep(100 * time.Millisecond)
		select {
		case out := <-output:
			// process died
			log.Println(out)
			return nil
		default:
		}
		conn, err := net.DialTimeout("tcp", marbleTestAddr, timeout)
		if err == nil {
			conn.Close()
			log.Println("Server started")
			return cmd.Process
		}
	}
}

func startMarbleClient(cfg marbleConfig) bool {
	out, err := getMarbleCmd(cfg).CombinedOutput()
	if err == nil {
		return true
	}

	if _, ok := err.(*exec.ExitError); ok {
		return false
	}

	panic(err.Error() + "\n" + string(out))
}
