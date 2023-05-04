// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package framework provides a testing framework for MarbleRun integration testing.
package framework

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	mconfig "github.com/edgelesssys/marblerun/marble/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// IntegrationTest is a testing framework for MarbleRun tests.
type IntegrationTest struct {
	assert  *assert.Assertions
	require *require.Assertions

	TestManifest        manifest.Manifest
	UpdatedManifest     manifest.Manifest
	BuildDir            string
	SimulationFlag      string
	NoEnclave           bool
	MeshServerAddr      string
	ClientServerAddr    string
	MarbleTestAddr      string
	transportSkipVerify http.RoundTripper
}

// New creates a new IntegrationTest.
func New(t *testing.T, buildDir, simulation string, noenclave bool,
	marbleTestAddr, meshServerAddr, clientServerAddr,
	testManifest, updatedManifest string,
) *IntegrationTest {
	i := &IntegrationTest{
		assert:  assert.New(t),
		require: require.New(t),

		BuildDir:            buildDir,
		SimulationFlag:      simulation,
		NoEnclave:           noenclave,
		MeshServerAddr:      meshServerAddr,
		ClientServerAddr:    clientServerAddr,
		MarbleTestAddr:      marbleTestAddr,
		transportSkipVerify: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	i.require.NoError(json.Unmarshal([]byte(testManifest), &i.TestManifest))
	i.require.NoError(json.Unmarshal([]byte(updatedManifest), &i.UpdatedManifest))

	return i
}

// UpdateManifest updates the manifest with the uniqueID, signerID, productID and securityVersion of the testing marble.
func (i IntegrationTest) UpdateManifest() {
	config, err := os.ReadFile(filepath.Join(i.BuildDir, "marble-test-config.json"))
	i.require.NoError(err)
	var cfg struct {
		SecurityVersion uint
		UniqueID        string
		SignerID        string
		ProductID       uint64
	}
	i.require.NoError(json.Unmarshal(config, &cfg))

	pkg := i.TestManifest.Packages["backend"]
	pkg.UniqueID = cfg.UniqueID
	pkg.SignerID = cfg.SignerID
	pkg.SecurityVersion = &cfg.SecurityVersion
	pkg.ProductID = &cfg.ProductID
	i.TestManifest.Packages["backend"] = pkg

	// Adjust unit test update manifest to work with the integration test
	i.UpdatedManifest.Packages["backend"] = i.UpdatedManifest.Packages["frontend"]
}

// CoordinatorConfig contains the configuration for the Coordinator.
type CoordinatorConfig struct {
	dnsNames string
	sealDir  string
}

// NewCoordinatorConfig creates a new CoordinatorConfig.
func NewCoordinatorConfig() CoordinatorConfig {
	sealDir, err := os.MkdirTemp("", "")
	if err != nil {
		panic(err)
	}
	return CoordinatorConfig{dnsNames: "localhost", sealDir: sealDir}
}

// Cleanup removes the seal directory.
func (c CoordinatorConfig) Cleanup() {
	if err := os.RemoveAll(c.sealDir); err != nil {
		panic(err)
	}
}

// StartCoordinator starts the Coordinator defined by the given config.
func (i IntegrationTest) StartCoordinator(cfg CoordinatorConfig) *os.Process {
	var cmd *exec.Cmd
	if i.NoEnclave {
		cmd = exec.Command(filepath.Join(i.BuildDir, "coordinator-noenclave"))
	} else {
		cmd = exec.Command("erthost", filepath.Join(i.BuildDir, "coordinator-enclave.signed"))
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL} // kill if parent dies
	cmd.Env = []string{
		MakeEnv(constants.MeshAddr, i.MeshServerAddr),
		MakeEnv(constants.ClientAddr, i.ClientServerAddr),
		MakeEnv(constants.DNSNames, cfg.dnsNames),
		MakeEnv(constants.SealDir, cfg.sealDir),
		i.SimulationFlag,
	}
	output := i.StartCommand(cmd)

	client := http.Client{Transport: i.transportSkipVerify}
	url := url.URL{Scheme: "https", Host: i.ClientServerAddr, Path: "status"}

	log.Println("Coordinator starting...")
	for {
		time.Sleep(10 * time.Millisecond)
		select {
		case out := <-output:
			// process died
			log.Println(out)
			return nil
		default:
		}

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url.String(), http.NoBody)
		i.require.NoError(err)

		resp, err := client.Do(req)
		if err == nil {
			log.Println("Coordinator started")
			resp.Body.Close()
			i.require.Equal(http.StatusOK, resp.StatusCode)
			return cmd.Process
		}
	}
}

// StartCommand starts the given command and returns a channel that contains the output.
func (i IntegrationTest) StartCommand(cmd *exec.Cmd) chan string {
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

// SetManifest sets the manifest of the Coordinator.
func (i IntegrationTest) SetManifest(manifest manifest.Manifest) ([]byte, error) {
	// Use ClientAPI to set Manifest
	client := http.Client{Transport: i.transportSkipVerify}
	clientAPIURL := url.URL{
		Scheme: "https",
		Host:   i.ClientServerAddr,
		Path:   "manifest",
	}

	manifestRaw, err := json.Marshal(manifest)
	i.require.NoError(err)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, clientAPIURL.String(), bytes.NewReader(manifestRaw))
	i.require.NoError(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	i.require.NoError(err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	i.require.NoError(err)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected %v, but /manifest returned %v: %v", http.StatusOK, resp.Status, string(body))
	}

	return body, nil
}

// SetUpdateManifest sets performs a manifest update for the Coordinator.
func (i IntegrationTest) SetUpdateManifest(manifest manifest.Manifest, certPEM []byte, key *rsa.PrivateKey) ([]byte, error) {
	// Setup requied client certificate for authentication
	privk, err := x509.MarshalPKCS8PrivateKey(key)
	i.require.NoError(err)

	cert, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privk}))
	i.require.NoError(err)

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}

	// Use ClientAPI to set Manifest
	client := http.Client{Transport: transport}
	clientAPIURL := url.URL{
		Scheme: "https",
		Host:   i.ClientServerAddr,
		Path:   "update",
	}

	manifestRaw, err := json.Marshal(manifest)
	i.require.NoError(err)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, clientAPIURL.String(), bytes.NewReader(manifestRaw))
	i.require.NoError(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	i.require.NoError(err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	i.require.NoError(err)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected %v, but /manifest returned %v: %v", http.StatusOK, resp.Status, string(body))
	}

	return body, nil
}

// SetRecover sets the recovery key of the Coordinator.
func (i IntegrationTest) SetRecover(recoveryKey []byte) error {
	client := http.Client{Transport: i.transportSkipVerify}
	clientAPIURL := url.URL{
		Scheme: "https",
		Host:   i.ClientServerAddr,
		Path:   "recover",
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, clientAPIURL.String(), bytes.NewReader(recoveryKey))
	i.require.NoError(err)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	i.require.NoError(err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	i.require.NoError(err)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected %v, but /recover returned %v: %v", http.StatusOK, resp.Status, string(body))
	}

	return nil
}

// GetStatus returns the status of the Coordinator.
func (i IntegrationTest) GetStatus() (string, error) {
	client := http.Client{Transport: i.transportSkipVerify}
	clientAPIURL := url.URL{
		Scheme: "https",
		Host:   i.ClientServerAddr,
		Path:   "status",
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, clientAPIURL.String(), http.NoBody)
	i.require.NoError(err)
	resp, err := client.Do(req)
	i.require.NoError(err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	i.require.NoError(err)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("expected %v, but /status returned %v: %v", http.StatusOK, resp.Status, string(body))
	}

	return string(body), nil
}

// MarbleConfig contains the configuration for a Marble.
type MarbleConfig struct {
	coordinatorAddr string
	marbleType      string
	dnsNames        string
	dataDir         string
}

// NewMarbleConfig creates a new MarbleConfig.
func NewMarbleConfig(coordinatorAddr, marbleType, dnsNames string) MarbleConfig {
	dataDir, err := os.MkdirTemp("", "")
	if err != nil {
		panic(err)
	}
	return MarbleConfig{
		coordinatorAddr: coordinatorAddr,
		marbleType:      marbleType,
		dnsNames:        dnsNames,
		dataDir:         dataDir,
	}
}

// Cleanup removes the data directory of the Marble.
func (c MarbleConfig) Cleanup() {
	if err := os.RemoveAll(c.dataDir); err != nil {
		panic(err)
	}
}

// GetMarbleCmd returns the command to start a Marble.
func (i IntegrationTest) GetMarbleCmd(cfg MarbleConfig) *exec.Cmd {
	var cmd *exec.Cmd
	if i.NoEnclave {
		cmd = exec.Command(filepath.Join(i.BuildDir, "marble-test-noenclave"))
	} else {
		cmd = exec.Command("erthost", filepath.Join(i.BuildDir, "marble-test-enclave.signed"))
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL} // kill if parent dies
	uuidFile := filepath.Join(cfg.dataDir, "uuid")
	cmd.Env = []string{
		MakeEnv(mconfig.CoordinatorAddr, cfg.coordinatorAddr),
		MakeEnv(mconfig.Type, cfg.marbleType),
		MakeEnv(mconfig.DNSNames, cfg.dnsNames),
		MakeEnv(mconfig.UUIDFile, uuidFile),
		MakeEnv("EDG_TEST_ADDR", i.MarbleTestAddr),
		i.SimulationFlag,
	}
	return cmd
}

// StartMarbleServer starts a Server Marble.
func (i IntegrationTest) StartMarbleServer(cfg MarbleConfig) *os.Process {
	cmd := i.GetMarbleCmd(cfg)
	output := i.StartCommand(cmd)

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
		conn, err := net.DialTimeout("tcp", i.MarbleTestAddr, timeout)
		if err == nil {
			conn.Close()
			log.Println("Server started")
			return cmd.Process
		}
	}
}

// StartMarbleClient starts a Client Marble.
func (i IntegrationTest) StartMarbleClient(cfg MarbleConfig) bool {
	out, err := i.GetMarbleCmd(cfg).CombinedOutput()
	if err == nil {
		return true
	}

	if _, ok := err.(*exec.ExitError); ok {
		return false
	}

	panic(err.Error() + "\n" + string(out))
}

// TriggerRecovery triggers a recovery.
func (i IntegrationTest) TriggerRecovery(coordinatorCfg CoordinatorConfig, coordinatorProc *os.Process) (*os.Process, string) {
	// get certificate
	log.Println("Save certificate before we try to recover.")
	client := http.Client{Transport: i.transportSkipVerify}
	clientAPIURL := url.URL{Scheme: "https", Host: i.ClientServerAddr, Path: "quote"}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, clientAPIURL.String(), http.NoBody)
	i.require.NoError(err)
	resp, err := client.Do(req)
	i.require.NoError(err)
	i.require.Equal(http.StatusOK, resp.StatusCode)
	quote, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	i.require.NoError(err)
	cert := gjson.GetBytes(quote, "data.Cert").String()
	i.require.NotEmpty(cert)

	// simulate restart of coordinator
	log.Println("Simulating a restart of the coordinator enclave...")
	log.Println("Killing the old instance")
	i.require.NoError(coordinatorProc.Kill())

	// Remove sealed encryption key to trigger recovery state
	log.Println("Deleting sealed key to trigger recovery state...")
	os.Remove(filepath.Join(coordinatorCfg.sealDir, stdstore.SealedKeyFname))

	// Restart server, we should be in recovery mode
	log.Println("Restarting the old instance")
	coordinatorProc = i.StartCoordinator(coordinatorCfg)
	i.require.NotNil(coordinatorProc)

	// Query status API, check if status response begins with Code 1 (recovery state)
	log.Println("Checking status...")
	statusResponse, err := i.GetStatus()
	i.require.NoError(err)
	i.assert.EqualValues(1, gjson.Get(statusResponse, "data.StatusCode").Int(), "Server is not in recovery state, but should be.")

	return coordinatorProc, cert
}

// VerifyCertAfterRecovery verifies the certificate after a recovery.
func (i IntegrationTest) VerifyCertAfterRecovery(cert string, coordinatorProc *os.Process, cfg CoordinatorConfig, assert *assert.Assertions, require *require.Assertions) *os.Process {
	// Test with certificate
	log.Println("Verifying certificate after recovery, without a restart.")
	pool := x509.NewCertPool()
	i.require.True(pool.AppendCertsFromPEM([]byte(cert)))
	client := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	clientAPIURL := url.URL{Scheme: "https", Host: i.ClientServerAddr, Path: "status"}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, clientAPIURL.String(), http.NoBody)
	require.NoError(err)
	resp, err := client.Do(req)
	i.require.NoError(err)
	resp.Body.Close()
	i.require.Equal(http.StatusOK, resp.StatusCode)

	// Simulate restart of coordinator
	log.Println("Simulating a restart of the coordinator enclave...")
	log.Println("Killing the old instance")
	i.require.NoError(coordinatorProc.Kill())

	// Restart server, we should be in recovery mode
	log.Println("Restarting the old instance")
	coordinatorProc = i.StartCoordinator(cfg)
	i.require.NotNil(coordinatorProc)

	// Finally, check if we survive a restart.
	log.Println("Restarted instance, now let's see if the state can be restored again successfully.")
	statusResponse, err := i.GetStatus()
	i.require.NoError(err)
	i.assert.EqualValues(3, gjson.Get(statusResponse, "data.StatusCode").Int(), "Server is in wrong status after recovery.")

	// test with certificate
	log.Println("Verifying certificate after restart.")
	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, clientAPIURL.String(), http.NoBody)
	require.NoError(err)
	resp, err = client.Do(req)
	i.require.NoError(err)
	resp.Body.Close()
	i.require.Equal(http.StatusOK, resp.StatusCode)

	return coordinatorProc
}

// VerifyResetAfterRecovery verifies the Coordinator after a recovery as been reset by setting a new manifest.
func (i IntegrationTest) VerifyResetAfterRecovery(coordinatorProc *os.Process, cfg CoordinatorConfig) *os.Process {
	// Check status after setting a new manifest, we should be able
	log.Println("Check if the manifest was accepted and we are ready to accept Marbles")
	statusResponse, err := i.GetStatus()
	i.require.NoError(err)
	i.assert.EqualValues(3, gjson.Get(statusResponse, "data.StatusCode").Int(), "Server is in wrong status after recovery.")

	// simulate restart of coordinator
	log.Println("Simulating a restart of the coordinator enclave...")
	log.Println("Killing the old instance")
	i.require.NoError(coordinatorProc.Kill())

	// Restart server, we should be in recovery mode
	log.Println("Restarting the old instance")
	coordinatorProc = i.StartCoordinator(cfg)
	i.require.NotNil(coordinatorProc)

	// Finally, check if we survive a restart.
	log.Println("Restarted instance, now let's see if the new state can be decrypted successfully...")
	statusResponse, err = i.GetStatus()
	i.require.NoError(err)
	i.assert.EqualValues(3, gjson.Get(statusResponse, "data.StatusCode").Int(), "Server is in wrong status after recovery.")

	return coordinatorProc
}

// MakeEnv returns a string that can be used as an environment variable.
func MakeEnv(key, value string) string {
	return fmt.Sprintf("%v=%v", key, value)
}
