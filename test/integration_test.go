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
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"net"
	"os"
	"testing"

	"github.com/edgelesssys/marblerun/api"
	corecrypto "github.com/edgelesssys/marblerun/coordinator/crypto"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/test/framework"
	"github.com/edgelesssys/marblerun/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	buildDir                                         = flag.String("b", "", "build dir")
	simulationMode                                   = flag.Bool("s", false, "Execute test in simulation mode (without real quoting)")
	noenclave                                        = flag.Bool("noenclave", false, "Do not run with erthost")
	meshServerAddr, clientServerAddr, marbleTestAddr string
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
	for _, sealMode := range []string{"", "Disabled", "ProductKey", "UniqueKey"} {
		t.Run("SealMode="+sealMode, func(t *testing.T) {
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
			f.TestManifest.Config.SealMode = sealMode
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
		})
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
	cert, _, _, err := api.VerifyCoordinator(context.Background(), clientServerAddr, api.VerifyOptions{InsecureSkipVerify: true})
	require.NoError(err)

	// create client certificate
	privk, err := x509.MarshalPKCS8PrivateKey(RecoveryPrivateKey)
	require.NoError(err)
	clCert, err := tls.X509KeyPair(AdminCert, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privk}))
	require.NoError(err)

	// test with certificate
	statusCode, _, err := api.GetStatus(context.Background(), clientServerAddr, cert)
	require.NoError(err)
	assert.Equal(2, statusCode)

	t.Log("Setting the Manifest")
	_, err = f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// test reading of secrets
	t.Log("Requesting a secret from the Coordinator")
	const secretName = "symmetricKeyShared"
	secrets, err := api.SecretGet(context.Background(), clientServerAddr, cert, &clCert, []string{secretName})
	require.NoError(err)
	secret := secrets[secretName]
	assert.Equal("symmetric-key", secret.Type)
	assert.EqualValues(128, secret.Size)
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
	var userSecrets map[string]manifest.UserSecret
	require.NoError(json.Unmarshal([]byte(UserSecrets), &userSecrets))
	require.NoError(api.SecretSet(context.Background(), clientServerAddr, nil, &clCert, userSecrets))

	// start the marble again
	t.Log("Starting the Client-Marble again, with the secret now set...")
	assert.True(f.StartMarbleClient(f.Ctx, clientCfg))
}

func TestRecoveryRestoreKey(t *testing.T) {
	for _, sealMode := range []string{"", "ProductKey", "UniqueKey"} {
		t.Run("SealMode="+sealMode, func(t *testing.T) {
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
			f.TestManifest.Config.SealMode = sealMode
			recoveryData, err := f.SetManifest(f.TestManifest)
			require.NoError(err, "failed to set Manifest")

			// start server
			t.Log("Starting a Server-Marble")
			serverCfg := framework.NewMarbleConfig(f.MeshServerAddr, "testMarbleServer", "server,backend,localhost")
			defer serverCfg.Cleanup()
			f.StartMarbleServer(f.Ctx, serverCfg)

			// Trigger recovery mode
			cancelCoordinator, cert := f.TriggerRecovery(cfg, cancelCoordinator)

			// Decrypt recovery data from when we set the manifest
			recoveryKey, err := api.DecryptRecoveryData(recoveryData["testRecKey1"], RecoveryPrivateKey)
			require.NoError(err, "Failed to decrypt the recovery data.")

			// Perform recovery
			require.NoError(f.SetRecover(recoveryKey))
			t.Log("Performed recovery, now checking status again...")
			statusCode, err := f.GetStatus()
			require.NoError(err)
			assert.EqualValues(3, statusCode, "Server is in wrong status after recovery.")

			// Verify if old certificate is still valid
			f.VerifyCertAfterRecovery(cert, cancelCoordinator, cfg)
		})
	}
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
	err = f.SetUpdateManifest(f.UpdatedManifest, AdminCert, RecoveryPrivateKey)
	require.NoError(err, "failed to set Update Manifest")

	// Try to start marbles again, should fail now due to increased minimum SecurityVersion
	t.Log("Starting the same bunch of outdated Client-Marbles again (should fail now)...")
	assert.False(f.StartMarbleClient(f.Ctx, clientCfg), "Did start successfully, but must not run successfully. The increased minimum SecurityVersion was ignored.")
	assert.False(f.StartMarbleClient(f.Ctx, clientCfg), "Did start successfully, but must not run successfully. The increased minimum SecurityVersion was ignored.")
}

func TestSignQuote(t *testing.T) {
	if *simulationMode || *noenclave {
		t.Skip("This test cannot be run in Simulation / No Enclave mode.")
	}

	f := newFramework(t)

	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	f.StartCoordinator(f.Ctx, cfg)

	// We can use any valid SGX quote for this test, e.g., the one from the Coordinator.
	validTrustedRoot, _, validQuote, err := api.VerifyCoordinator(context.Background(), clientServerAddr, api.VerifyOptions{InsecureSkipVerify: true})
	require.NoError(t, err)

	// enable the endpoint
	f.TestManifest.Config.FeatureGates = []string{"SignQuoteEndpoint"}
	_, err = f.SetManifest(f.TestManifest)
	require.NoError(t, err)

	testCases := map[string]struct {
		quote         []byte
		trustedRoot   *x509.Certificate
		wantSignErr   bool
		wantVerifyErr bool
	}{
		"valid": {
			quote:       validQuote,
			trustedRoot: validTrustedRoot,
		},
		"invalid quote": {
			quote: func() []byte {
				quote := append([]byte(nil), validQuote...)
				quote[453] ^= 1 // corrupt the signature
				return quote
			}(),
			trustedRoot: validTrustedRoot,
			wantSignErr: true,
		},
		"invalid root": {
			quote: validQuote,
			trustedRoot: func() *x509.Certificate {
				// use valid, but wrong root cert
				root, _, err := corecrypto.GenerateCert(validTrustedRoot.DNSNames, validTrustedRoot.Subject.CommonName, nil, nil, nil)
				require.NoError(t, err)
				return root
			}(),
			wantVerifyErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			sig, tcbStatus, err := api.SignQuote(context.Background(), clientServerAddr, validTrustedRoot, tc.quote)
			if tc.wantSignErr {
				assert.Error(err)
				return
			}
			require.NoError(err)

			isValid := api.VerifySignedQuote(tc.trustedRoot, tc.quote, sig, tcbStatus)
			if tc.wantVerifyErr {
				assert.False(isValid)
				return
			}
			require.True(isValid)

			// check that verification fails for wrong tcb status or invalid signature
			assert.False(api.VerifySignedQuote(tc.trustedRoot, tc.quote, sig, tcbStatus+1))
			sig[2] ^= 1
			assert.False(api.VerifySignedQuote(tc.trustedRoot, tc.quote, sig, tcbStatus))
		})
	}
}

func newFramework(t *testing.T) *framework.IntegrationTest {
	f := framework.New(t, *buildDir, simFlag, *noenclave, marbleTestAddr, meshServerAddr, clientServerAddr, IntegrationManifestJSON, UpdateManifest)
	f.UpdateManifest()
	return f
}
