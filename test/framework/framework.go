/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// Package framework provides a testing framework for MarbleRun integration testing.
package framework

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/edgelesssys/marblerun/api"
	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	mconfig "github.com/edgelesssys/marblerun/marble/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// IntegrationTest is a testing framework for MarbleRun tests.
type IntegrationTest struct {
	t       *testing.T
	assert  *assert.Assertions
	require *require.Assertions

	Ctx              context.Context
	TestManifest     manifest.Manifest
	UpdatedManifest  manifest.Manifest
	BuildDir         string
	SimulationFlag   string
	NoEnclave        bool
	MeshServerAddr   string
	ClientServerAddr string
	MarbleTestAddr   string
}

// New creates a new IntegrationTest.
func New(t *testing.T, buildDir, simulation string, noenclave bool,
	marbleTestAddr, meshServerAddr, clientServerAddr,
	testManifest, updatedManifest string,
) *IntegrationTest {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	i := &IntegrationTest{
		t:       t,
		assert:  assert.New(t),
		require: require.New(t),

		Ctx:              ctx,
		BuildDir:         buildDir,
		SimulationFlag:   simulation,
		NoEnclave:        noenclave,
		MeshServerAddr:   meshServerAddr,
		ClientServerAddr: clientServerAddr,
		MarbleTestAddr:   marbleTestAddr,
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
	extraEnv []string
}

// NewCoordinatorConfig creates a new CoordinatorConfig.
func NewCoordinatorConfig(extraEnv ...string) CoordinatorConfig {
	sealDir, err := os.MkdirTemp("", "")
	if err != nil {
		panic(err)
	}
	return CoordinatorConfig{
		dnsNames: "localhost",
		sealDir:  sealDir,
		extraEnv: extraEnv,
	}
}

// Cleanup removes the seal directory.
func (c CoordinatorConfig) Cleanup() {
	if err := os.RemoveAll(c.sealDir); err != nil {
		panic(err)
	}
}

// StartCoordinator starts the Coordinator defined by the given config.
// The returned func cancels the Coordinator and waits until it exited.
func (i IntegrationTest) StartCoordinator(ctx context.Context, cfg CoordinatorConfig) func() {
	var cmd *exec.Cmd
	if i.NoEnclave {
		cmd = exec.CommandContext(ctx, filepath.Join(i.BuildDir, "coordinator-noenclave"))
	} else {
		cmd = exec.CommandContext(ctx, "erthost", filepath.Join(i.BuildDir, "coordinator-enclave.signed"))
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL} // kill if parent dies
	cmd.Env = []string{
		MakeEnv(constants.MeshAddr, i.MeshServerAddr),
		MakeEnv(constants.ClientAddr, i.ClientServerAddr),
		MakeEnv(constants.DNSNames, cfg.dnsNames),
		MakeEnv(constants.SealDir, cfg.sealDir),
		i.SimulationFlag,
	}
	cmd.Env = append(cmd.Env, cfg.extraEnv...)
	cmdErr := i.StartCommand("coor", cmd)

	i.t.Log("Coordinator starting...")
	for {
		time.Sleep(10 * time.Millisecond)
		select {
		case err := <-cmdErr:
			// process died
			i.t.Fatal(err)
		default:
		}

		if _, _, err := api.GetStatus(context.Background(), i.ClientServerAddr, nil); err == nil {
			i.t.Log("Coordinator started")
			return func() {
				_ = cmd.Cancel()
				<-cmdErr
			}
		}
	}
}

// StartCommand starts the given command and returns a channel that contains the error (or nil) when the process exited.
func (i IntegrationTest) StartCommand(friendlyName string, cmd *exec.Cmd) chan error {
	stdout, err := cmd.StdoutPipe()
	i.require.NoError(err)
	stderr, err := cmd.StderrPipe()
	i.require.NoError(err)
	i.require.NoError(cmd.Start())

	log := func(pipe io.ReadCloser, pipeName string) {
		for scanner := bufio.NewScanner(pipe); scanner.Scan(); {
			i.t.Log(friendlyName, pipeName+":", scanner.Text())
		}
	}
	go log(stdout, "out")
	go log(stderr, "err")

	waitErr := make(chan error)
	go func() {
		waitErr <- cmd.Wait()
		close(waitErr)
	}()

	// On test end, wait until the process actually exited so that the next test can start cleanly.
	i.t.Cleanup(func() {
		_ = cmd.Cancel()
		<-waitErr
	})
	return waitErr
}

// SetManifest sets the manifest of the Coordinator.
func (i IntegrationTest) SetManifest(manifest manifest.Manifest) (map[string][]byte, error) {
	manifestRaw, err := json.Marshal(manifest)
	i.require.NoError(err)
	return api.ManifestSet(context.Background(), i.ClientServerAddr, nil, manifestRaw)
}

// SetUpdateManifest sets performs a manifest update for the Coordinator.
func (i IntegrationTest) SetUpdateManifest(manifest manifest.Manifest, certPEM []byte, key *rsa.PrivateKey) error {
	// Setup requied client certificate for authentication
	privk, err := x509.MarshalPKCS8PrivateKey(key)
	i.require.NoError(err)

	cert, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privk}))
	i.require.NoError(err)

	manifestRaw, err := json.Marshal(manifest)
	i.require.NoError(err)

	return api.ManifestUpdateApply(context.Background(), i.ClientServerAddr, nil, manifestRaw, &cert)
}

// SetRecover sets the recovery key of the Coordinator.
func (i IntegrationTest) SetRecover(recoveryKey []byte) error {
	_, _, err := api.Recover(context.Background(), i.ClientServerAddr, api.VerifyOptions{InsecureSkipVerify: true}, recoveryKey)
	return err
}

// GetStatus returns the status of the Coordinator.
func (i IntegrationTest) GetStatus() (int, error) {
	code, _, err := api.GetStatus(context.Background(), i.ClientServerAddr, nil)
	return code, err
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
func (i IntegrationTest) GetMarbleCmd(ctx context.Context, cfg MarbleConfig) *exec.Cmd {
	var cmd *exec.Cmd
	if i.NoEnclave {
		cmd = exec.CommandContext(ctx, filepath.Join(i.BuildDir, "marble-test-noenclave"))
	} else {
		cmd = exec.CommandContext(ctx, "erthost", filepath.Join(i.BuildDir, "marble-test-enclave.signed"))
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL} // kill if parent dies
	uuidFile := filepath.Join(cfg.dataDir, "uuid")
	cmd.Env = []string{
		MakeEnv(mconfig.CoordinatorAddr, cfg.coordinatorAddr),
		MakeEnv(mconfig.Type, cfg.marbleType),
		MakeEnv(mconfig.DNSNames, cfg.dnsNames),
		MakeEnv(mconfig.UUIDFile, uuidFile),
		MakeEnv("EDG_TEST_ADDR", i.MarbleTestAddr),
		MakeEnv(constants.ClientAddr, i.ClientServerAddr),
		i.SimulationFlag,
	}
	return cmd
}

// StartMarbleServer starts a Server Marble.
func (i IntegrationTest) StartMarbleServer(ctx context.Context, cfg MarbleConfig) {
	cmd := i.GetMarbleCmd(ctx, cfg)
	cmdErr := i.StartCommand("serv", cmd)

	i.t.Log("Waiting for server...")
	timeout := time.Second * 5
	for {
		time.Sleep(100 * time.Millisecond)
		select {
		case err := <-cmdErr:
			// process died
			i.t.Fatal(err)
		default:
		}
		conn, err := net.DialTimeout("tcp", i.MarbleTestAddr, timeout)
		if err == nil {
			conn.Close()
			i.t.Log("Server started")
			return
		}
	}
}

// StartMarbleClient starts a Client Marble.
func (i IntegrationTest) StartMarbleClient(ctx context.Context, cfg MarbleConfig) bool {
	cmd := i.GetMarbleCmd(ctx, cfg)

	// Tests sometimes time out with a goroutine at `cmd.Wait()` waiting for the client to end. This is hard to reproduce.
	// Maybe the client process doesn't exit cleanly. Temporarily increase OE log level to see if we can get more info.
	// TODO remove this when the bug is identified
	cmd.Env = append(cmd.Env, "OE_LOG_LEVEL=INFO")

	err := <-i.StartCommand("clnt", cmd)
	if err == nil {
		return true
	}

	if _, ok := err.(*exec.ExitError); ok {
		return false
	}

	i.require.NoError(err)
	return false
}

// TriggerRecovery triggers a recovery.
func (i IntegrationTest) TriggerRecovery(coordinatorCfg CoordinatorConfig, cancelCoordinator func()) (func(), *x509.Certificate) {
	// get certificate
	i.t.Log("Save certificate before we try to recover.")
	cert, _, _, err := api.VerifyCoordinator(context.Background(), i.ClientServerAddr, api.VerifyOptions{InsecureSkipVerify: true})
	i.require.NoError(err)

	// simulate restart of coordinator
	i.t.Log("Simulating a restart of the coordinator enclave...")
	i.t.Log("Killing the old instance")
	cancelCoordinator()

	// Remove sealed encryption key to trigger recovery state
	i.t.Log("Deleting sealed key to trigger recovery state...")
	os.Remove(filepath.Join(coordinatorCfg.sealDir, stdstore.SealedKeyFname))

	// Restart server, we should be in recovery mode
	i.t.Log("Restarting the old instance")
	cancelCoordinator = i.StartCoordinator(i.Ctx, coordinatorCfg)

	// Query status API, check if status response begins with Code 1 (recovery state)
	i.t.Log("Checking status...")
	statusCode, err := i.GetStatus()
	i.require.NoError(err)
	i.assert.EqualValues(1, statusCode, "Server is not in recovery state, but should be.")

	return cancelCoordinator, cert
}

// VerifyCertAfterRecovery verifies the certificate after a recovery.
func (i IntegrationTest) VerifyCertAfterRecovery(cert *x509.Certificate, cancelCoordinator func(), cfg CoordinatorConfig) func() {
	// Test with certificate
	i.t.Log("Verifying certificate after recovery, without a restart.")
	_, _, err := api.GetStatus(context.Background(), i.ClientServerAddr, cert)
	i.require.NoError(err)

	// Simulate restart of coordinator
	i.t.Log("Simulating a restart of the coordinator enclave...")
	i.t.Log("Killing the old instance")
	cancelCoordinator()

	// Restart server, we should be in recovery mode
	i.t.Log("Restarting the old instance")
	cancelCoordinator = i.StartCoordinator(i.Ctx, cfg)

	// Finally, check if we survive a restart.
	i.t.Log("Restarted instance, now let's see if the state can be restored again successfully.")
	statusCode, err := i.GetStatus()
	i.require.NoError(err)
	i.assert.EqualValues(3, statusCode, "Server is in wrong status after recovery.")

	// test with certificate
	i.t.Log("Verifying certificate after restart.")
	_, _, err = api.GetStatus(context.Background(), i.ClientServerAddr, cert)
	i.require.NoError(err)

	return cancelCoordinator
}

// VerifyResetAfterRecovery verifies the Coordinator after a recovery as been reset by setting a new manifest.
func (i IntegrationTest) VerifyResetAfterRecovery(cancelCoordinator func(), cfg CoordinatorConfig) func() {
	// Check status after setting a new manifest, we should be able
	i.t.Log("Check if the manifest was accepted and we are ready to accept Marbles")
	statusCode, err := i.GetStatus()
	i.require.NoError(err)
	i.assert.EqualValues(3, statusCode, "Server is in wrong status after recovery.")

	// simulate restart of coordinator
	i.t.Log("Simulating a restart of the coordinator enclave...")
	i.t.Log("Killing the old instance")
	cancelCoordinator()

	// Restart server, we should be in recovery mode
	i.t.Log("Restarting the old instance")
	cancelCoordinator = i.StartCoordinator(i.Ctx, cfg)

	// Finally, check if we survive a restart.
	i.t.Log("Restarted instance, now let's see if the new state can be decrypted successfully...")
	statusCode, err = i.GetStatus()
	i.require.NoError(err)
	i.assert.EqualValues(3, statusCode, "Server is in wrong status after recovery.")

	return cancelCoordinator
}

// MakeEnv returns a string that can be used as an environment variable.
func MakeEnv(key, value string) string {
	return fmt.Sprintf("%v=%v", key, value)
}
