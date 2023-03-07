// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/edgelesssys/marblerun/test/framework"
	"github.com/edgelesssys/marblerun/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

var (
	buildDir                                         = flag.String("b", "", "build dir")
	simulationMode                                   = flag.Bool("s", false, "Execute test in simulation mode (without real quoting)")
	noenclave                                        = flag.Bool("noenclave", false, "Do not run with erthost")
	meshServerAddr, clientServerAddr, marbleTestAddr string
	transportSkipVerify                              = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	simFlag                                          string
)

func TestMain(m *testing.M) {
	flag.Parse()
	if *buildDir == "" {
		log.Fatalln("You must provide the path of the build directory using the -b flag.")
	}
	if _, err := os.Stat(*buildDir); err != nil {
		log.Fatalln(err)
	}

	if *simulationMode {
		simFlag = framework.MakeEnv("OE_SIMULATION", "1")
	} else {
		simFlag = framework.MakeEnv("OE_SIMULATION", "0")
	}

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

// sanity test of the integration test environment
func TestTest(t *testing.T) {
	assert := assert.New(t)
	f := newFramework(t)

	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	assert.Nil(f.StartCoordinator(cfg).Kill())

	marbleCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleClient", "localhost")
	defer marbleCfg.Cleanup()
	assert.False(f.StartMarbleClient(marbleCfg))
}

func TestMarbleAPI(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newFramework(t)

	// start Coordinator
	log.Println("Starting a coordinator enclave")
	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	coordinatorProc := f.StartCoordinator(cfg)
	require.NotNil(coordinatorProc)
	defer coordinatorProc.Kill()

	// set Manifest
	log.Println("Setting the Manifest")
	_, err := f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// start server
	log.Println("Starting a Server-Marble...")
	serverCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleServer", "server,backend,localhost")
	defer serverCfg.Cleanup()
	serverProc := f.StartMarbleServer(serverCfg)
	require.NotNil(serverProc, "failed to start server-marble")
	defer serverProc.Kill()

	// start clients
	log.Println("Starting a bunch of Client-Marbles...")
	clientCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleClient", "client,frontend,localhost")
	defer clientCfg.Cleanup()
	assert.True(f.StartMarbleClient(clientCfg))
	assert.True(f.StartMarbleClient(clientCfg))
	if !*simulationMode && !*noenclave {
		// start bad marbles (would be accepted if we run in SimulationMode)
		badCfg := framework.NewMarbleConfig(meshServerAddr, "badMarble", "bad,localhost")
		defer badCfg.Cleanup()
		assert.False(f.StartMarbleClient(badCfg))
		assert.False(f.StartMarbleClient(badCfg))
	}
}

func TestRestart(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newFramework(t)

	log.Println("Testing the restart capabilities")
	// start Coordinator
	log.Println("Starting a coordinator enclave...")
	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	coordinatorProc := f.StartCoordinator(cfg)
	require.NotNil(coordinatorProc)

	// set Manifest
	_, err := f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// start server
	log.Println("Starting a Server-Marble...")
	serverCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleServer", "server,backend,localhost")
	defer serverCfg.Cleanup()
	serverProc := f.StartMarbleServer(serverCfg)
	require.NotNil(serverProc, "failed to start server-marble")
	defer serverProc.Kill()

	// start clients
	log.Println("Starting a bunch of Client-Marbles...")
	clientCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleClient", "client,frontend,localhost")
	defer clientCfg.Cleanup()
	assert.True(f.StartMarbleClient(clientCfg))
	assert.True(f.StartMarbleClient(clientCfg))

	// simulate restart of coordinator
	log.Println("Simulating a restart of the coordinator enclave...")
	log.Println("Killing the old instance")
	require.NoError(coordinatorProc.Kill())
	log.Println("Restarting the old instance")
	coordinatorProc = f.StartCoordinator(cfg)
	require.NotNil(coordinatorProc)
	defer coordinatorProc.Kill()

	// try do malicious update of manifest
	log.Println("Trying to set a new Manifest, which should already be set")
	_, err = f.SetManifest(f.TestManifest)
	assert.Error(err, "expected updating of manifest to fail, but succeeded")

	// start a bunch of client marbles and assert they still work with old server marble
	log.Println("Starting a bunch of Client-Marbles, which should still authenticate successfully with the Server-Marble...")
	assert.True(f.StartMarbleClient(clientCfg))
	assert.True(f.StartMarbleClient(clientCfg))
}

func TestClientAPI(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newFramework(t)

	// start Coordinator
	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	coordinatorProc := f.StartCoordinator(cfg)
	require.NotNil(coordinatorProc, "could not start coordinator")
	defer coordinatorProc.Kill()

	// get certificate
	client := http.Client{Transport: transportSkipVerify}
	clientAPIURL := url.URL{Scheme: "https", Host: clientServerAddr, Path: "quote"}
	resp, err := client.Get(clientAPIURL.String())
	require.NoError(err)
	require.Equal(http.StatusOK, resp.StatusCode)
	quote, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(err)
	cert := gjson.Get(string(quote), "data.Cert").String()
	require.NotEmpty(cert)

	// create client with certificates
	pool := x509.NewCertPool()
	require.True(pool.AppendCertsFromPEM([]byte(cert)))
	privk, err := x509.MarshalPKCS8PrivateKey(RecoveryPrivateKey)
	require.NoError(err)
	clCert, err := tls.X509KeyPair(AdminCert, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privk}))
	require.NoError(err)
	client = http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{clCert},
		RootCAs:      pool,
	}}}

	// test with certificate
	clientAPIURL.Path = "manifest"
	resp, err = client.Get(clientAPIURL.String())
	require.NoError(err)
	require.Equal(http.StatusOK, resp.StatusCode)
	manifest, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(err)
	assert.JSONEq(`{"status":"success","data":{"ManifestSignatureRootECDSA":null,"ManifestSignature":"","Manifest":null}}`, string(manifest))

	log.Println("Setting the Manifest")
	_, err = f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// test reading of secrets
	log.Println("Requesting a secret from the Coordinator")
	clientAPIURL.Path = "secrets"
	clientAPIURL.RawQuery = "s=symmetricKeyShared"
	resp, err = client.Get(clientAPIURL.String())
	require.NoError(err)
	require.Equal(http.StatusOK, resp.StatusCode)
	secret, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(err)
	assert.Contains(string(secret), `{"status":"success","data":{"symmetricKeyShared":{"Type":"symmetric-key","Size":128,`)
}

func TestSettingSecrets(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newFramework(t)

	// start Coordinator
	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	coordinatorProc := f.StartCoordinator(cfg)
	require.NotNil(coordinatorProc, "could not start coordinator")
	defer coordinatorProc.Kill()

	log.Println("Setting the Manifest")
	_, err := f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// create client with certificates
	privk, err := x509.MarshalPKCS8PrivateKey(RecoveryPrivateKey)
	require.NoError(err)
	clCert, err := tls.X509KeyPair(AdminCert, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privk}))
	require.NoError(err)
	client := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates:       []tls.Certificate{clCert},
		InsecureSkipVerify: true,
	}}}

	// start server
	log.Println("Starting a Server-Marble...")
	serverCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleServer", "server,backend,localhost")
	defer serverCfg.Cleanup()
	serverProc := f.StartMarbleServer(serverCfg)
	require.NotNil(serverProc, "failed to start server-marble")
	defer serverProc.Kill()

	// start a marble
	log.Println("Starting a Client-Marble with unset secret, this should fail...")
	clientCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleUnset", "client,frontend,localhost")
	defer clientCfg.Cleanup()
	assert.False(f.StartMarbleClient(clientCfg))

	// test setting a secret
	log.Println("Setting a custom secret")
	clientAPIURL := url.URL{Scheme: "https", Host: clientServerAddr, Path: "secrets"}
	_, err = client.Post(clientAPIURL.String(), "application/json", strings.NewReader(UserSecrets))
	require.NoError(err)

	// start the marble again
	log.Println("Starting the Client-Marble again, with the secret now set...")
	assert.True(f.StartMarbleClient(clientCfg))
}

func TestRecoveryRestoreKey(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newFramework(t)

	log.Println("Testing recovery...")
	log.Println("Starting a coordinator enclave")
	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	coordinatorProc := f.StartCoordinator(cfg)
	require.NotNil(coordinatorProc, "could not start coordinator")
	defer coordinatorProc.Kill()

	// set Manifest
	log.Println("Setting the Manifest")
	recoveryResponse, err := f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// start server
	log.Println("Starting a Server-Marble")
	serverCfg := framework.NewMarbleConfig(f.MeshServerAddr, "testMarbleServer", "server,backend,localhost")
	defer serverCfg.Cleanup()
	serverProc := f.StartMarbleServer(serverCfg)
	require.NotNil(serverProc, "failed to start server-marble")
	defer serverProc.Kill()

	// Trigger recovery mode
	coordinatorProc, cert := f.TriggerRecovery(cfg, coordinatorProc)
	defer coordinatorProc.Kill()

	// Decode & Decrypt recovery data from when we set the manifest
	key := gjson.GetBytes(recoveryResponse, "data.RecoverySecrets.testRecKey1").String()
	recoveryDataEncrypted, err := base64.StdEncoding.DecodeString(key)
	require.NoError(err, "Failed to base64 decode recovery data.")
	recoveryKey, err := util.DecryptOAEP(RecoveryPrivateKey, recoveryDataEncrypted)
	require.NoError(err, "Failed to RSA OAEP decrypt the recovery data.")

	// Perform recovery
	require.NoError(f.SetRecover(recoveryKey))
	log.Println("Performed recovery, now checking status again...")
	statusResponse, err := f.GetStatus()
	require.NoError(err)
	assert.EqualValues(3, gjson.Get(statusResponse, "data.StatusCode").Int(), "Server is in wrong status after recovery.")

	// Verify if old certificate is still valid
	coordinatorProc = f.VerifyCertAfterRecovery(cert, coordinatorProc, cfg, assert, require)
	require.NoError(coordinatorProc.Kill())
}

func TestRecoveryReset(t *testing.T) {
	require := require.New(t)
	f := newFramework(t)

	log.Println("Testing recovery...")
	log.Println("Starting a coordinator enclave")
	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	coordinatorProc := f.StartCoordinator(cfg)
	require.NotNil(coordinatorProc, "could not start coordinator")
	defer coordinatorProc.Kill()

	// set Manifest
	log.Println("Setting the Manifest")
	_, err := f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// start server
	log.Println("Starting a Server-Marble")
	serverCfg := framework.NewMarbleConfig(f.MeshServerAddr, "testMarbleServer", "server,backend,localhost")
	defer serverCfg.Cleanup()
	serverProc := f.StartMarbleServer(serverCfg)
	require.NotNil(serverProc, "failed to start server-marble")
	defer serverProc.Kill()

	// Trigger recovery mode
	coordinatorProc, _ = f.TriggerRecovery(cfg, coordinatorProc)
	defer coordinatorProc.Kill()

	// Set manifest again
	log.Println("Setting the Manifest")
	_, err = f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// Verify if a new manifest has been set correctly and we are off to a fresh start
	coordinatorProc = f.VerifyResetAfterRecovery(coordinatorProc, cfg)
	require.NoError(coordinatorProc.Kill())
}

func TestManifestUpdate(t *testing.T) {
	// This file cannot be run in DOS mode ;)
	if *simulationMode || *noenclave {
		t.Skip("This test cannot be run in Simulation / No Enclave mode.")
		return
	}
	f := newFramework(t)

	assert := assert.New(t)
	require := require.New(t)

	// start Coordinator
	log.Println("Starting a coordinator enclave")
	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	coordinatorProc := f.StartCoordinator(cfg)
	require.NotNil(coordinatorProc)
	defer coordinatorProc.Kill()

	// set Manifest
	log.Println("Setting the Manifest")
	_, err := f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// start server
	log.Println("Starting a Server-Marble")
	serverCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleServer", "server,backend,localhost")
	defer serverCfg.Cleanup()
	serverProc := f.StartMarbleServer(serverCfg)
	require.NotNil(serverProc, "failed to start server-marble")
	defer serverProc.Kill()

	// start clients
	log.Println("Starting a bunch of Client-Marbles (should start successfully)...")
	clientCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleClient", "client,frontend,localhost")
	defer clientCfg.Cleanup()
	assert.True(f.StartMarbleClient(clientCfg))
	assert.True(f.StartMarbleClient(clientCfg))
	// start bad marbles (would be accepted if we run in SimulationMode)
	badCfg := framework.NewMarbleConfig(meshServerAddr, "badMarble", "bad,localhost")
	defer badCfg.Cleanup()
	assert.False(f.StartMarbleClient(badCfg))
	assert.False(f.StartMarbleClient(badCfg))

	// Set the update manifest
	log.Println("Setting the Update Manifest")
	_, err = f.SetUpdateManifest(f.UpdatedManifest, AdminCert, RecoveryPrivateKey)
	require.NoError(err, "failed to set Update Manifest")

	// Try to start marbles again, should fail now due to increased minimum SecurityVersion
	log.Println("Starting the same bunch of outdated Client-Marbles again (should fail now)...")
	assert.False(f.StartMarbleClient(clientCfg), "Did start successfully, but must not run successfully. The increased minimum SecurityVersion was ignored.")
	assert.False(f.StartMarbleClient(clientCfg), "Did start successfully, but must not run successfully. The increased minimum SecurityVersion was ignored.")
}

func newFramework(t *testing.T) *framework.IntegrationTest {
	f := framework.New(t, *buildDir, simFlag, *noenclave, marbleTestAddr, meshServerAddr, clientServerAddr, IntegrationManifestJSON, UpdateManifest)
	f.UpdateManifest()
	return f
}
