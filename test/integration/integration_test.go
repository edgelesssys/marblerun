//go:build integration

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/edgelesssys/marblerun/api"
	corecrypto "github.com/edgelesssys/marblerun/coordinator/crypto"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/edgelesssys/marblerun/test"
	"github.com/edgelesssys/marblerun/test/integration/framework"
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
	privk, err := x509.MarshalPKCS8PrivateKey(test.RecoveryPrivateKeyOne)
	require.NoError(err)
	clCert, err := tls.X509KeyPair(test.AdminCert, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privk}))
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
	privk, err := x509.MarshalPKCS8PrivateKey(test.RecoveryPrivateKeyOne)
	require.NoError(err)
	clCert, err := tls.X509KeyPair(test.AdminCert, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privk}))
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
	require.NoError(json.Unmarshal([]byte(test.UserSecrets), &userSecrets))
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

			// Coordinator can restart automatically
			cancelCoordinator()
			cancelCoordinator = f.StartCoordinator(f.Ctx, cfg)
			t.Log("Restarted Coordinator, checking status again...")
			statusCode, err := f.GetStatus()
			require.NoError(err)
			assert.EqualValues(int(state.AcceptingMarbles), statusCode, "Server is in wrong status after restart.")

			// Trigger recovery mode
			cancelCoordinator, cert := f.TriggerRecovery(cfg, cancelCoordinator)

			// Decrypt recovery data from when we set the manifest
			recoveryKey, err := api.DecryptRecoveryData(recoveryData["testRecKey1"], test.RecoveryPrivateKeyOne)
			require.NoError(err, "Failed to decrypt the recovery data.")

			// Perform recovery
			require.NoError(f.SetRecover(recoveryKey, test.RecoveryPrivateKeyOne))
			t.Log("Performed recovery, now checking status again...")
			statusCode, err = f.GetStatus()
			require.NoError(err)
			assert.EqualValues(int(state.AcceptingMarbles), statusCode, "Server is in wrong status after recovery.")

			// Verify if old certificate is still valid
			cancelCoordinator = f.VerifyCertAfterRecovery(cert, cancelCoordinator, cfg)
			cancelCoordinator()
		})
	}
}

func TestRecoverySealedKeyStateBinding(t *testing.T) {
	if *noenclave {
		t.Skip("This test cannot be run in No Enclave mode.")
		return
	}

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
			f.TestManifest.Config.FeatureGates = []string{"MonotonicCounter"}
			recoveryData, err := f.SetManifest(f.TestManifest)
			require.NoError(err, "failed to set Manifest")

			// start server
			t.Log("Starting a Server-Marble")
			serverCfg := framework.NewMarbleConfig(f.MeshServerAddr, "testMarbleServer", "server,backend,localhost")
			defer serverCfg.Cleanup()
			f.StartMarbleServer(f.Ctx, serverCfg)

			// Coordinator can restart automatically
			cancelCoordinator()
			cancelCoordinator = f.StartCoordinator(f.Ctx, cfg)
			t.Log("Restarted Coordinator, checking status again...")
			statusCode, err := f.GetStatus()
			require.NoError(err)
			assert.EqualValues(int(state.AcceptingMarbles), statusCode, "Server is in wrong status after restart.")

			// Get certificate before triggering recovery
			cert, _, _, err := api.VerifyCoordinator(context.Background(), f.ClientServerAddr, api.VerifyOptions{InsecureSkipVerify: true})
			require.NoError(err)

			// Save backup of the encryption key
			sealedEncryptionKey, err := os.ReadFile(filepath.Join(cfg.SealDir, stdstore.SealedKeyFname))
			require.NoError(err)

			// Start a marble which sets a monotonic counter
			// This will update the state and re-seal the key
			marbleCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleMonotonicCounter", "localhost")
			defer marbleCfg.Cleanup()
			assert.True(f.StartMarbleClient(f.Ctx, marbleCfg))

			// Stop the Coordinator and replace the sealed key with the backup
			cancelCoordinator()
			require.NoError(os.WriteFile(filepath.Join(cfg.SealDir, stdstore.SealedKeyFname), sealedEncryptionKey, 0o600))

			// Since the key backup is bound to a different state, the
			// Coordinator should not be able to recovery automatically
			cancelCoordinator = f.StartCoordinator(f.Ctx, cfg)
			defer cancelCoordinator()
			statusCode, err = f.GetStatus()
			require.NoError(err)
			assert.EqualValues(int(state.Recovery), statusCode, "Server is in wrong status after restart.")

			// Decrypt recovery data from when we set the manifest
			recoveryKey, err := api.DecryptRecoveryData(recoveryData["testRecKey1"], test.RecoveryPrivateKeyOne)
			require.NoError(err, "Failed to decrypt the recovery data.")

			// Perform recovery
			require.NoError(f.SetRecover(recoveryKey, test.RecoveryPrivateKeyOne))
			t.Log("Performed recovery, now checking status again...")
			statusCode, err = f.GetStatus()
			require.NoError(err)
			assert.EqualValues(int(state.AcceptingMarbles), statusCode, "Server is in wrong status after recovery.")

			// Verify if old certificate is still valid
			cancelCoordinator = f.VerifyCertAfterRecovery(cert, cancelCoordinator, cfg)
			cancelCoordinator()
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
	_, _, missingAcks, err := f.SetUpdateManifest(f.UpdatedManifest, test.AdminCert, test.RecoveryPrivateKeyOne)
	require.NoError(err, "failed to set Update Manifest")
	assert.Equal(0, missingAcks, "failed to set Update Manifest")

	// Try to start marbles again, should fail now due to increased minimum SecurityVersion
	t.Log("Starting the same bunch of outdated Client-Marbles again (should fail now)...")
	assert.False(f.StartMarbleClient(f.Ctx, clientCfg), "Did start successfully, but must not run successfully. The increased minimum SecurityVersion was ignored.")
	assert.False(f.StartMarbleClient(f.Ctx, clientCfg), "Did start successfully, but must not run successfully. The increased minimum SecurityVersion was ignored.")
}

func TestExternalConnectionToMarble(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newFramework(t)

	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	f.StartCoordinator(f.Ctx, cfg)

	_, err := f.SetManifest(f.TestManifest)
	require.NoError(err)

	serverCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleServerNoClientAuth", "localhost")
	defer serverCfg.Cleanup()
	f.StartMarbleServer(f.Ctx, serverCfg)

	rootCert, intermediateCert, _, err := api.VerifyCoordinator(context.Background(), clientServerAddr, api.VerifyOptions{InsecureSkipVerify: true})
	require.NoError(err)

	req, err := http.NewRequestWithContext(f.Ctx, http.MethodGet, "https://"+marbleTestAddr, http.NoBody)
	require.NoError(err)

	// test that an external app can connect and verify with both the root and the intermediate certificate
	for _, root := range []*x509.Certificate{rootCert, intermediateCert} {
		roots := x509.NewCertPool()
		roots.AddCert(root)
		client := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
		resp, err := client.Do(req)
		assert.NoError(err)
		if err == nil {
			resp.Body.Close()
			assert.Equal(http.StatusOK, resp.StatusCode)
		}
	}
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

func TestMonotonicCounter(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newFramework(t)

	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	f.StartCoordinator(f.Ctx, cfg)

	f.TestManifest.Config.FeatureGates = []string{"MonotonicCounter"}
	_, err := f.SetManifest(f.TestManifest)
	require.NoError(err)

	marbleCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleMonotonicCounter", "localhost")
	defer marbleCfg.Cleanup()
	assert.True(f.StartMarbleClient(f.Ctx, marbleCfg))
}

func TestMultiPartyRecoveryRestoreKey(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	log.Println("Testing multi-party recovery, restore the seal key with two secrets...")

	f := framework.New(t, *buildDir, simFlag, *noenclave, marbleTestAddr, meshServerAddr, clientServerAddr, test.IntegrationMultiPartyManifestJSON, test.IntegrationMultiPartyManifestJSON)

	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	cancelCoordinator := f.StartCoordinator(f.Ctx, cfg)

	// set Manifest
	log.Println("Setting the Manifest")
	recoveryData, err := f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// Trigger recovery mode
	cancelCoordinator, cert := f.TriggerRecovery(cfg, cancelCoordinator)

	// Decode & Decrypt recovery data from when we set the manifest
	log.Println("Decoding and decrypting recovery data...")
	secretOne, err := api.DecryptRecoveryData(recoveryData["testRecKey1"], test.RecoveryPrivateKeyOne)
	require.NoError(err, "Failed to decrypt the recovery data for testRecKey1.")
	secretTwo, err := api.DecryptRecoveryData(recoveryData["testRecKey2"], test.RecoveryPrivateKeyTwo)
	require.NoError(err, "Failed to decrypt the recovery data for testRecKey2.")

	// Upload first secret to server, server should stay in recovery mode
	log.Println("Uploading first decrypted secret...")
	require.NoError(f.SetRecover(secretOne, test.RecoveryPrivateKeyOne))
	log.Println("Coordinator successfully accepted first decrypted secret.")
	statusCode, err := f.GetStatus()
	require.NoError(err)
	assert.EqualValues(1, statusCode, "Server is not in recovery state, but should be.")

	// Upload second secret to server, server should be recovered
	log.Println("Uploading second decrypted secret...")
	require.NoError(f.SetRecover(secretTwo, test.RecoveryPrivateKeyTwo))
	log.Println("Coordinator successfully accepted second decrypted secret.")
	log.Println("Successfully performed recovery, now checking status again...")
	statusCode, err = f.GetStatus()
	require.NoError(err)
	assert.EqualValues(3, statusCode, "Server is in wrong status after recovery.")

	// Verify if a new manifest has been set correctly and we are off to a fresh start
	f.VerifyCertAfterRecovery(cert, cancelCoordinator, cfg)
}

func TestMultiPartyRecoveryReset(t *testing.T) {
	require := require.New(t)

	t.Log("Testing multi-party recovery, reset state back to scratch with a new manifest...")

	var multiPartyRecoveryManifest manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.IntegrationMultiPartyManifestJSON), &multiPartyRecoveryManifest))

	f := framework.New(t, *buildDir, simFlag, *noenclave, marbleTestAddr, meshServerAddr, clientServerAddr, test.IntegrationMultiPartyManifestJSON, test.IntegrationMultiPartyManifestJSON)

	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	cancelCoordinator := f.StartCoordinator(f.Ctx, cfg)

	// Set Manifest
	t.Log("Setting the Manifest")
	_, err := f.SetManifest(multiPartyRecoveryManifest)
	require.NoError(err, "failed to set Manifest")

	cancelCoordinator, _ = f.TriggerRecovery(cfg, cancelCoordinator)

	// Set manifest again
	t.Log("Setting the Manifest")
	_, err = f.SetManifest(multiPartyRecoveryManifest)
	require.NoError(err, "failed to set Manifest")

	f.VerifyResetAfterRecovery(cancelCoordinator, cfg)
}

func TestRecoveryEncryptedRecoverySecret(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	log.Println("Testing recovery with encrypted recovery secrets...")

	f := framework.New(t, *buildDir, simFlag, *noenclave, marbleTestAddr, meshServerAddr, clientServerAddr, test.IntegrationMultiPartyManifestJSON, test.IntegrationMultiPartyManifestJSON)

	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	cancelCoordinator := f.StartCoordinator(f.Ctx, cfg)

	// set Manifest
	log.Println("Setting the Manifest")
	recoveryData, err := f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// Trigger recovery mode
	cancelCoordinator, cert := f.TriggerRecovery(cfg, cancelCoordinator)

	// Decode & Decrypt recovery data from when we set the manifest
	log.Println("Decoding and decrypting recovery data...")
	secretOne, err := api.DecryptRecoveryData(recoveryData["testRecKey1"], test.RecoveryPrivateKeyOne)
	require.NoError(err, "Failed to decrypt the recovery data for testRecKey1.")
	secretTwo, err := api.DecryptRecoveryData(recoveryData["testRecKey2"], test.RecoveryPrivateKeyTwo)
	require.NoError(err, "Failed to decrypt the recovery data for testRecKey2.")

	// Create signatures over the recovery secrets
	sig1, err := util.SignPKCS1v15(test.RecoveryPrivateKeyOne, secretOne)
	require.NoError(err, "Failed to create signature for recovery secret one.")
	sig2, err := util.SignPKCS1v15(test.RecoveryPrivateKeyTwo, secretTwo)
	require.NoError(err, "Failed to create signature for recovery secret two.")

	// Retrieve recovery ephemeral public key from Coordinator
	recoveryPub, _, err := api.RecoveryPublicKey(f.Ctx, f.ClientServerAddr, api.VerifyOptions{InsecureSkipVerify: true})
	require.NoError(err, "Failed to retrieve recovery ephemeral public key from Coordinator.")

	// Encrypt recovery secrets with recovery ephemeral public key
	encryptedSecretOne, err := api.EncryptRecoverySecretWithEphemeralKey(secretOne, recoveryPub)
	require.NoError(err, "Failed to encrypt recovery secret one with recovery ephemeral public key.")
	encryptedSecretTwo, err := api.EncryptRecoverySecretWithEphemeralKey(secretTwo, recoveryPub)
	require.NoError(err, "Failed to encrypt recovery secret two with recovery ephemeral public key.")

	// Upload first secret to server, server should stay in recovery mode
	log.Println("Uploading first decrypted secret...")
	// require.NoError(f.SetRecover(encryptedSecretOne, test.RecoveryPrivateKeyOne))
	remaining, _, err := api.RecoverWithSignature(f.Ctx, f.ClientServerAddr, api.VerifyOptions{InsecureSkipVerify: true}, encryptedSecretOne, sig1)
	require.NoError(err, "Failed to upload first recovery secret.")
	require.EqualValues(1, remaining, "Wrong number of remaining secrets after uploading first secret.")
	log.Println("Coordinator successfully accepted first decrypted secret.")
	statusCode, err := f.GetStatus()
	require.NoError(err)
	assert.EqualValues(1, statusCode, "Server is not in recovery state, but should be.")

	// Upload second secret to server, server should be recovered
	log.Println("Uploading second decrypted secret...")
	// require.NoError(f.SetRecover(encryptedSecretTwo, test.RecoveryPrivateKeyTwo))
	remaining, _, err = api.RecoverWithSignature(f.Ctx, f.ClientServerAddr, api.VerifyOptions{InsecureSkipVerify: true}, encryptedSecretTwo, sig2)
	require.NoError(err, "Failed to upload second recovery secret.")
	require.EqualValues(0, remaining, "Wrong number of remaining secrets after uploading second secret.")
	log.Println("Coordinator successfully accepted second decrypted secret.")
	log.Println("Successfully performed recovery, now checking status again...")
	statusCode, err = f.GetStatus()
	require.NoError(err)
	assert.EqualValues(3, statusCode, "Server is in wrong status after recovery.")

	// Verify if a new manifest has been set correctly and we are off to a fresh start
	f.VerifyCertAfterRecovery(cert, cancelCoordinator, cfg)
}

func TestShamirRecovery(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	t.Log("Testing Shamir Secret Sharing recovery...")
	var multiPartyRecoveryManifest manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.IntegrationMultiPartyManifestJSON), &multiPartyRecoveryManifest))
	multiPartyRecoveryManifest.Config.RecoveryThreshold = 2
	key, err := rsa.GenerateKey(rand.Reader, 3096)
	require.NoError(err)
	pkixPublicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(err)
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkixPublicKey,
	}
	pubPEM := pem.EncodeToMemory(publicKeyBlock)
	multiPartyRecoveryManifest.RecoveryKeys["recKey3"] = string(pubPEM)
	recoveryMnf, err := json.Marshal(multiPartyRecoveryManifest)
	require.NoError(err)
	f := framework.New(t, *buildDir, simFlag, *noenclave, marbleTestAddr, meshServerAddr, clientServerAddr, string(recoveryMnf), string(recoveryMnf))
	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	cancelCoordinator := f.StartCoordinator(f.Ctx, cfg)

	// set Manifest
	log.Println("Setting the Manifest")
	recoveryData, err := f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// Trigger recovery mode
	cancelCoordinator, cert := f.TriggerRecovery(cfg, cancelCoordinator)

	// Decode & Decrypt recovery data from when we set the manifest
	log.Println("Decoding and decrypting recovery data...")
	secretOne, err := api.DecryptRecoveryData(recoveryData["testRecKey1"], test.RecoveryPrivateKeyOne)
	require.NoError(err, "Failed to decrypt the recovery data for testRecKey1.")
	secretTwo, err := api.DecryptRecoveryData(recoveryData["testRecKey2"], test.RecoveryPrivateKeyTwo)
	require.NoError(err, "Failed to decrypt the recovery data for testRecKey2.")

	// Upload first secret to server, server should stay in recovery mode
	log.Println("Uploading first decrypted secret...")
	require.NoError(f.SetRecover(secretOne, test.RecoveryPrivateKeyOne))
	log.Println("Coordinator successfully accepted first decrypted secret.")
	statusCode, err := f.GetStatus()
	require.NoError(err)
	assert.EqualValues(1, statusCode, "Server is not in recovery state, but should be.")

	// Upload second secret to server, server should be recovered
	log.Println("Uploading second decrypted secret...")
	require.NoError(f.SetRecover(secretTwo, test.RecoveryPrivateKeyTwo))
	log.Println("Coordinator successfully accepted second decrypted secret.")
	log.Println("Successfully performed recovery, now checking status again...")
	statusCode, err = f.GetStatus()
	require.NoError(err)
	assert.EqualValues(3, statusCode, "Server is in wrong status after recovery.")

	// Verify if a new manifest has been set correctly and we are off to a fresh start
	f.VerifyCertAfterRecovery(cert, cancelCoordinator, cfg)
}

func TestShamirRecoveryEncryptedSecrets(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	t.Log("Testing Shamir Secret Sharing recovery...")
	var multiPartyRecoveryManifest manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.IntegrationMultiPartyManifestJSON), &multiPartyRecoveryManifest))
	multiPartyRecoveryManifest.Config.RecoveryThreshold = 2
	key, err := rsa.GenerateKey(rand.Reader, 3096)
	require.NoError(err)
	pkixPublicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(err)
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkixPublicKey,
	}
	pubPEM := pem.EncodeToMemory(publicKeyBlock)
	multiPartyRecoveryManifest.RecoveryKeys["recKey3"] = string(pubPEM)
	recoveryMnf, err := json.Marshal(multiPartyRecoveryManifest)
	require.NoError(err)
	f := framework.New(t, *buildDir, simFlag, *noenclave, marbleTestAddr, meshServerAddr, clientServerAddr, string(recoveryMnf), string(recoveryMnf))
	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	cancelCoordinator := f.StartCoordinator(f.Ctx, cfg)

	// set Manifest
	log.Println("Setting the Manifest")
	recoveryData, err := f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// Trigger recovery mode
	cancelCoordinator, cert := f.TriggerRecovery(cfg, cancelCoordinator)

	// Decode & Decrypt recovery data from when we set the manifest
	log.Println("Decoding and decrypting recovery data...")
	secretOne, err := api.DecryptRecoveryData(recoveryData["testRecKey1"], test.RecoveryPrivateKeyOne)
	require.NoError(err, "Failed to decrypt the recovery data for testRecKey1.")
	secretTwo, err := api.DecryptRecoveryData(recoveryData["testRecKey2"], test.RecoveryPrivateKeyTwo)
	require.NoError(err, "Failed to decrypt the recovery data for testRecKey2.")

	// Create signatures over the recovery secrets
	sig1, err := util.SignPKCS1v15(test.RecoveryPrivateKeyOne, secretOne)
	require.NoError(err, "Failed to create signature for recovery secret one.")
	sig2, err := util.SignPKCS1v15(test.RecoveryPrivateKeyTwo, secretTwo)
	require.NoError(err, "Failed to create signature for recovery secret two.")

	// Retrieve recovery ephemeral public key from Coordinator
	recoveryPub, _, err := api.RecoveryPublicKey(f.Ctx, f.ClientServerAddr, api.VerifyOptions{InsecureSkipVerify: true})
	require.NoError(err, "Failed to retrieve recovery ephemeral public key from Coordinator.")

	// Encrypt recovery secrets with recovery ephemeral public key
	encryptedSecretOne, err := api.EncryptRecoverySecretWithEphemeralKey(secretOne, recoveryPub)
	require.NoError(err, "Failed to encrypt recovery secret one with recovery ephemeral public key.")
	encryptedSecretTwo, err := api.EncryptRecoverySecretWithEphemeralKey(secretTwo, recoveryPub)
	require.NoError(err, "Failed to encrypt recovery secret two with recovery ephemeral public key.")

	// Upload first secret to server, server should stay in recovery mode
	log.Println("Uploading first decrypted secret...")
	remaining, _, err := api.RecoverWithSignature(f.Ctx, f.ClientServerAddr, api.VerifyOptions{InsecureSkipVerify: true}, encryptedSecretOne, sig1)
	require.NoError(err, "Failed to upload first recovery secret.")
	require.EqualValues(2, remaining, "Wrong number of remaining secrets after uploading first secret.") // With Shamir, we don't know how many secrets remain until threshold is met
	log.Println("Coordinator successfully accepted first decrypted secret.")
	statusCode, err := f.GetStatus()
	require.NoError(err)
	assert.EqualValues(1, statusCode, "Server is not in recovery state, but should be.")

	// Upload second secret to server, server should be recovered
	log.Println("Uploading second decrypted secret...")
	remaining, _, err = api.RecoverWithSignature(f.Ctx, f.ClientServerAddr, api.VerifyOptions{InsecureSkipVerify: true}, encryptedSecretTwo, sig2)
	require.NoError(err, "Failed to upload second recovery secret.")
	require.EqualValues(0, remaining, "Wrong number of remaining secrets after uploading second secret.")
	log.Println("Coordinator successfully accepted second decrypted secret.")
	log.Println("Successfully performed recovery, now checking status again...")
	statusCode, err = f.GetStatus()
	require.NoError(err)
	assert.EqualValues(3, statusCode, "Server is in wrong status after recovery.")

	// Verify if a new manifest has been set correctly and we are off to a fresh start
	f.VerifyCertAfterRecovery(cert, cancelCoordinator, cfg)
}

func TestRecoveryKeyChange(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	log.Println("Testing recovery key change on update...")

	var mnf manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.IntegrationMultiPartyManifestJSON), &mnf))
	mnf.Config.UpdateThreshold = 1 // simplify test by having only one admin approve updates
	mnfJSON, err := json.Marshal(mnf)
	require.NoError(err)

	var updateMnf manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.IntegrationMultiPartyUpdateJSON), &updateMnf))
	recPub1, recPriv1 := test.GenerateTestRecoveryKey()
	recPub2, recPriv2 := test.GenerateTestRecoveryKey()
	updateMnf.RecoveryKeys = map[string]string{
		"newRecKey1": string(recPub1),
		"newRecKey2": string(recPub2),
	}
	updateMnfJSON, err := json.Marshal(updateMnf)
	require.NoError(err)

	f := framework.New(t, *buildDir, simFlag, *noenclave, marbleTestAddr, meshServerAddr, clientServerAddr, string(mnfJSON), string(updateMnfJSON))
	f.UpdateManifest()

	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	cancelCoordinator := f.StartCoordinator(f.Ctx, cfg)

	recoveryData, err := f.SetManifest(f.TestManifest)
	require.NoError(err)

	statusCode, err := f.GetStatus()
	require.NoError(err)
	assert.EqualValues(state.AcceptingMarbles, statusCode)

	// Trigger recovery mode
	cancelCoordinator, coordCert := f.TriggerRecovery(cfg, cancelCoordinator)

	// Decode & Decrypt recovery data from when we set the manifest
	log.Println("Decoding and decrypting recovery data...")
	secretOne, err := api.DecryptRecoveryData(recoveryData["testRecKey1"], test.RecoveryPrivateKeyOne)
	require.NoError(err, "Failed to decrypt the recovery data for testRecKey1.")
	secretTwo, err := api.DecryptRecoveryData(recoveryData["testRecKey2"], test.RecoveryPrivateKeyTwo)
	require.NoError(err, "Failed to decrypt the recovery data for testRecKey2.")

	// Upload first secret to server, server should stay in recovery mode
	log.Println("Uploading first decrypted secret...")
	require.NoError(f.SetRecover(secretOne, test.RecoveryPrivateKeyOne))
	log.Println("Coordinator successfully accepted first decrypted secret.")
	statusCode, err = f.GetStatus()
	require.NoError(err)
	assert.EqualValues(state.Recovery, statusCode, "Server is not in recovery state, but should be.")

	// Upload second secret to server, server should be recovered
	log.Println("Uploading second decrypted secret...")
	require.NoError(f.SetRecover(secretTwo, test.RecoveryPrivateKeyTwo))
	log.Println("Coordinator successfully accepted second decrypted secret.")
	log.Println("Successfully performed recovery, now checking status again...")
	statusCode, err = f.GetStatus()
	require.NoError(err)
	assert.EqualValues(state.AcceptingMarbles, statusCode, "Server is in wrong status after recovery.")

	cancelCoordinator = f.VerifyCertAfterRecovery(coordCert, cancelCoordinator, cfg)

	log.Println("Updating manifest to change recovery keys...")
	newRecoveryData, _, missingAcks, err := f.SetUpdateManifest(updateMnf, test.AdminOneCert, test.AdminOnePrivKey)
	require.NoError(err)
	require.Equal(0, missingAcks)
	require.Len(newRecoveryData, 2, "Expected 2 recovery secrets after update.")
	assert.NotEqual(recoveryData, newRecoveryData, "Expected 2 new recovery secrets after update.")

	// Coordinator should be able to recover on its own if the sealing key is available
	cancelCoordinator = f.VerifyCertAfterRecovery(coordCert, cancelCoordinator, cfg)

	// Trigger recovery mode again and recover with the new keys
	cancelCoordinator, _ = f.TriggerRecovery(cfg, cancelCoordinator)
	defer cancelCoordinator()
	log.Println("Decoding and decrypting recovery data...")
	secretOne, err = api.DecryptRecoveryData(newRecoveryData["newRecKey1"], recPriv1)
	require.NoError(err, "Failed to decrypt the recovery data for testRecKey1.")
	secretTwo, err = api.DecryptRecoveryData(newRecoveryData["newRecKey2"], recPriv2)
	require.NoError(err, "Failed to decrypt the recovery data for testRecKey2.")

	// Upload first secret to server, server should stay in recovery mode
	log.Println("Uploading first decrypted secret...")
	require.NoError(f.SetRecover(secretOne, recPriv1))
	log.Println("Coordinator successfully accepted first decrypted secret.")
	statusCode, err = f.GetStatus()
	require.NoError(err)
	assert.EqualValues(state.Recovery, statusCode, "Server is not in recovery state, but should be.")

	// Upload second secret to server, server should be recovered
	log.Println("Uploading second decrypted secret...")
	require.NoError(f.SetRecover(secretTwo, recPriv2))
	log.Println("Coordinator successfully accepted second decrypted secret.")
	log.Println("Successfully performed recovery, now checking status again...")
	statusCode, err = f.GetStatus()
	require.NoError(err)
	assert.EqualValues(state.AcceptingMarbles, statusCode, "Server is in wrong status after recovery.")
}

func TestMultiPartyManifestUpdate(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	log.Println("Testing multi-party manifest update...")

	f := framework.New(t, *buildDir, simFlag, *noenclave, marbleTestAddr, meshServerAddr, clientServerAddr, test.IntegrationMultiPartyManifestJSON, test.IntegrationMultiPartyUpdateJSON)
	f.UpdateManifest()

	cfg := framework.NewCoordinatorConfig()
	defer cfg.Cleanup()
	f.StartCoordinator(f.Ctx, cfg)

	_, err := f.SetManifest(f.TestManifest)
	require.NoError(err)

	log.Println("Starting a Server-Marble")
	serverCfg := framework.NewMarbleConfig(meshServerAddr, "testMarbleServer", "server,backend,localhost")
	defer serverCfg.Cleanup()
	serverCtx, cancelServer := context.WithCancel(f.Ctx)
	f.StartMarbleServer(serverCtx, serverCfg)

	manifestRaw, err := json.Marshal(f.UpdatedManifest)
	require.NoError(err)

	log.Println("Initiating multi-party manifest update...")
	adminOneTLSCert, err := tlsKeyPair(test.AdminOnePrivKey, test.AdminOneCert)
	require.NoError(err)
	newRecoveryData, _, missingAcks, err := api.ManifestUpdateApply(f.Ctx, f.ClientServerAddr, nil, manifestRaw, &adminOneTLSCert)
	require.NoError(err)
	require.Equal(1, missingAcks)
	assert.Empty(newRecoveryData)

	log.Println("Acknowledging multi-party manifest update...")
	adminTwoTLSCert, err := tlsKeyPair(test.AdminTwoPrivKey, test.AdminTwoCert)
	require.NoError(err)
	newRecoveryData, _, missingAcks, err = api.ManifestUpdateAcknowledge(f.Ctx, f.ClientServerAddr, nil, manifestRaw, &adminTwoTLSCert)
	require.NoError(err)
	require.Equal(0, missingAcks)
	assert.Empty(newRecoveryData)
	log.Println("Successfully performed multi-party manifest update.")

	log.Println("Restarting Server-Marble. This should now fail...")
	cancelServer()
	serverCmd := f.GetMarbleCmd(f.Ctx, serverCfg)
	serverChan := make(chan error, 1)
	go func() {
		serverChan <- serverCmd.Run()
	}()
	select {
	case err := <-serverChan:
		require.Error(err, "server-marble exited, but without error")
	case <-time.After(20 * time.Second):
		t.Error("server-marble was able to restart after manifest update")
	}
}

func newFramework(t *testing.T) *framework.IntegrationTest {
	f := framework.New(t, *buildDir, simFlag, *noenclave, marbleTestAddr, meshServerAddr, clientServerAddr, test.IntegrationManifestJSON, test.UpdateManifest)
	f.UpdateManifest()
	return f
}

func tlsKeyPair(key *rsa.PrivateKey, certPEM []byte) (tls.Certificate, error) {
	privk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privk}))
}
