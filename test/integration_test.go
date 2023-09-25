// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package test

import (
	"context"
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

func TestTest(t *testing.T) {
	// sanity test of the integration test environment
	assert := assert.New(t)
	f := newFramework(t)

	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	f.StartCoordinator(f.Ctx, cfg)

	marbleCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleClient", "localhost")
	defer marbleCfg.Cleanup()
	assert.False(f.StartMarbleClient(f.Ctx, marbleCfg))
}

func TestMarbleAPI(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newFramework(t)

	// start Coordinator
	t.Log("Starting a coordinator enclave")
	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	f.StartCoordinator(f.Ctx, cfg)

	// set Manifest
	t.Log("Setting the Manifest")
	_, err := f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// start server
	t.Log("Starting a Server-Marble...")
	serverCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleServer", "server,backend,localhost")
	defer serverCfg.Cleanup()
	f.StartMarbleServer(f.Ctx, serverCfg)

	// start clients
	t.Log("Starting a bunch of Client-Marbles...")
	clientCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleClient", "client,frontend,localhost")
	defer clientCfg.Cleanup()
	assert.True(f.StartMarbleClient(f.Ctx, clientCfg))
	assert.True(f.StartMarbleClient(f.Ctx, clientCfg))
	if !*simulationMode && !*noenclave {
		// start bad marbles (would be accepted if we run in SimulationMode)
		badCfg := framework.NewMarbleConfig(meshServerAddr, "badMarble", "bad,localhost")
		defer badCfg.Cleanup()
		assert.False(f.StartMarbleClient(f.Ctx, badCfg))
		assert.False(f.StartMarbleClient(f.Ctx, badCfg))
	}
}

func TestRestart(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newFramework(t)

	t.Log("Testing the restart capabilities")
	// start Coordinator
	t.Log("Starting a coordinator enclave...")
	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	cancelCoordinator := f.StartCoordinator(f.Ctx, cfg)

	// set Manifest
	_, err := f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// start server
	t.Log("Starting a Server-Marble...")
	serverCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleServer", "server,backend,localhost")
	defer serverCfg.Cleanup()
	f.StartMarbleServer(f.Ctx, serverCfg)

	// start clients
	t.Log("Starting a bunch of Client-Marbles...")
	clientCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleClient", "client,frontend,localhost")
	defer clientCfg.Cleanup()
	assert.True(f.StartMarbleClient(f.Ctx, clientCfg))
	assert.True(f.StartMarbleClient(f.Ctx, clientCfg))

	// simulate restart of coordinator
	t.Log("Simulating a restart of the coordinator enclave...")
	t.Log("Killing the old instance")
	cancelCoordinator()
	t.Log("Restarting the old instance")
	f.StartCoordinator(f.Ctx, cfg)

	// try do malicious update of manifest
	t.Log("Trying to set a new Manifest, which should already be set")
	_, err = f.SetManifest(f.TestManifest)
	assert.Error(err, "expected updating of manifest to fail, but succeeded")

	// start a bunch of client marbles and assert they still work with old server marble
	t.Log("Starting a bunch of Client-Marbles, which should still authenticate successfully with the Server-Marble...")
	assert.True(f.StartMarbleClient(f.Ctx, clientCfg))
	assert.True(f.StartMarbleClient(f.Ctx, clientCfg))
}

func TestClientAPI(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newFramework(t)

	// start Coordinator
	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	f.StartCoordinator(f.Ctx, cfg)

	// get certificate
	client := http.Client{Transport: transportSkipVerify}
	clientAPIURL := url.URL{Scheme: "https", Host: clientServerAddr, Path: "quote"}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, clientAPIURL.String(), http.NoBody)
	require.NoError(err)
	resp, err := client.Do(req)
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
	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, clientAPIURL.String(), http.NoBody)
	require.NoError(err)
	resp, err = client.Do(req)
	require.NoError(err)

	require.Equal(http.StatusOK, resp.StatusCode)
	manifest, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(err)
	assert.JSONEq(`{"status":"success","data":{"ManifestSignatureRootECDSA":null,"ManifestSignature":"","Manifest":null}}`, string(manifest))

	t.Log("Setting the Manifest")
	_, err = f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// test reading of secrets
	t.Log("Requesting a secret from the Coordinator")
	clientAPIURL.Path = "secrets"
	clientAPIURL.RawQuery = "s=symmetricKeyShared"
	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, clientAPIURL.String(), http.NoBody)
	require.NoError(err)
	resp, err = client.Do(req)
	require.NoError(err)

	require.Equal(http.StatusOK, resp.StatusCode)
	secret, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
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
	f.StartCoordinator(f.Ctx, cfg)

	t.Log("Setting the Manifest")
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
	t.Log("Starting a Server-Marble...")
	serverCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleServer", "server,backend,localhost")
	defer serverCfg.Cleanup()
	f.StartMarbleServer(f.Ctx, serverCfg)

	// start a marble
	t.Log("Starting a Client-Marble with unset secret, this should fail...")
	clientCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleUnset", "client,frontend,localhost")
	defer clientCfg.Cleanup()
	assert.False(f.StartMarbleClient(f.Ctx, clientCfg))

	// test setting a secret
	t.Log("Setting a custom secret")
	clientAPIURL := url.URL{Scheme: "https", Host: clientServerAddr, Path: "secrets"}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, clientAPIURL.String(), strings.NewReader(UserSecrets))
	require.NoError(err)
	resp, err := client.Do(req)
	require.NoError(err)
	resp.Body.Close()

	// start the marble again
	t.Log("Starting the Client-Marble again, with the secret now set...")
	assert.True(f.StartMarbleClient(f.Ctx, clientCfg))
}

func TestRecoveryRestoreKey(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newFramework(t)

	t.Log("Testing recovery...")
	t.Log("Starting a coordinator enclave")
	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	cancelCoordinator := f.StartCoordinator(f.Ctx, cfg)

	// set Manifest
	t.Log("Setting the Manifest")
	recoveryResponse, err := f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// start server
	t.Log("Starting a Server-Marble")
	serverCfg := framework.NewMarbleConfig(f.MeshServerAddr, "testMarbleServer", "server,backend,localhost")
	defer serverCfg.Cleanup()
	f.StartMarbleServer(f.Ctx, serverCfg)

	// Trigger recovery mode
	cancelCoordinator, cert := f.TriggerRecovery(cfg, cancelCoordinator)

	// Decode & Decrypt recovery data from when we set the manifest
	key := gjson.GetBytes(recoveryResponse, "data.RecoverySecrets.testRecKey1").String()
	recoveryDataEncrypted, err := base64.StdEncoding.DecodeString(key)
	require.NoError(err, "Failed to base64 decode recovery data.")
	recoveryKey, err := util.DecryptOAEP(RecoveryPrivateKey, recoveryDataEncrypted)
	require.NoError(err, "Failed to RSA OAEP decrypt the recovery data.")

	// Perform recovery
	require.NoError(f.SetRecover(recoveryKey))
	t.Log("Performed recovery, now checking status again...")
	statusResponse, err := f.GetStatus()
	require.NoError(err)
	assert.EqualValues(3, gjson.Get(statusResponse, "data.StatusCode").Int(), "Server is in wrong status after recovery.")

	// Verify if old certificate is still valid
	f.VerifyCertAfterRecovery(cert, cancelCoordinator, cfg)
}

func TestRecoveryReset(t *testing.T) {
	require := require.New(t)
	f := newFramework(t)

	t.Log("Testing recovery...")
	t.Log("Starting a coordinator enclave")
	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	cancelCoordinator := f.StartCoordinator(f.Ctx, cfg)

	// set Manifest
	t.Log("Setting the Manifest")
	_, err := f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// start server
	t.Log("Starting a Server-Marble")
	serverCfg := framework.NewMarbleConfig(f.MeshServerAddr, "testMarbleServer", "server,backend,localhost")
	defer serverCfg.Cleanup()
	f.StartMarbleServer(f.Ctx, serverCfg)

	// Trigger recovery mode
	cancelCoordinator, _ = f.TriggerRecovery(cfg, cancelCoordinator)

	// Set manifest again
	t.Log("Setting the Manifest")
	_, err = f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// Verify if a new manifest has been set correctly and we are off to a fresh start
	f.VerifyResetAfterRecovery(cancelCoordinator, cfg)
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
	t.Log("Starting a coordinator enclave")
	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	f.StartCoordinator(f.Ctx, cfg)

	// set Manifest
	t.Log("Setting the Manifest")
	_, err := f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// start server
	t.Log("Starting a Server-Marble")
	serverCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleServer", "server,backend,localhost")
	defer serverCfg.Cleanup()
	f.StartMarbleServer(f.Ctx, serverCfg)

	// start clients
	t.Log("Starting a bunch of Client-Marbles (should start successfully)...")
	clientCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleClient", "client,frontend,localhost")
	defer clientCfg.Cleanup()
	assert.True(f.StartMarbleClient(f.Ctx, clientCfg))
	assert.True(f.StartMarbleClient(f.Ctx, clientCfg))
	// start bad marbles (would be accepted if we run in SimulationMode)
	badCfg := framework.NewMarbleConfig(meshServerAddr, "badMarble", "bad,localhost")
	defer badCfg.Cleanup()
	assert.False(f.StartMarbleClient(f.Ctx, badCfg))
	assert.False(f.StartMarbleClient(f.Ctx, badCfg))

	// Set the update manifest
	t.Log("Setting the Update Manifest")
	_, err = f.SetUpdateManifest(f.UpdatedManifest, AdminCert, RecoveryPrivateKey)
	require.NoError(err, "failed to set Update Manifest")

	// Try to start marbles again, should fail now due to increased minimum SecurityVersion
	t.Log("Starting the same bunch of outdated Client-Marbles again (should fail now)...")
	assert.False(f.StartMarbleClient(f.Ctx, clientCfg), "Did start successfully, but must not run successfully. The increased minimum SecurityVersion was ignored.")
	assert.False(f.StartMarbleClient(f.Ctx, clientCfg), "Did start successfully, but must not run successfully. The increased minimum SecurityVersion was ignored.")
}

func newFramework(t *testing.T) *framework.IntegrationTest {
	f := framework.New(t, *buildDir, simFlag, *noenclave, marbleTestAddr, meshServerAddr, clientServerAddr, IntegrationManifestJSON, UpdateManifest)
	f.UpdateManifest()
	return f
}
