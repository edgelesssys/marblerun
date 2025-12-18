//go:build integration && hsmsealing

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package test

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/edgelesssys/marblerun/api"
	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/keyrelease"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/edgelesssys/marblerun/test"
	"github.com/edgelesssys/marblerun/test/integration/framework"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHSMSealing(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	t.Log("Testing HSM Sealing")
	var hsmSealingManifest manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.IntegrationMultiPartyManifestJSON), &hsmSealingManifest))
	hsmSealingManifest.Config.FeatureGates = append(hsmSealingManifest.Config.FeatureGates, manifest.FeatureAzureHSMSealing)
	// Remove second user and recovery key since we don't need them for this test
	delete(hsmSealingManifest.Users, "admin-2")
	delete(hsmSealingManifest.RecoveryKeys, "testRecKey2")

	mnf, err := json.Marshal(hsmSealingManifest)
	require.NoError(err)

	f := framework.New(t, *buildDir, simFlag, *noenclave, marbleTestAddr, meshServerAddr, clientServerAddr, string(mnf), string(mnf))
	cfg := framework.NewCoordinatorConfig([]string{
		framework.MakeEnv(constants.EnvAzureHSMKeyName, "stub"),
		framework.MakeEnv(constants.EnvAzureHSMKeyVersion, "stub"),
		framework.MakeEnv(constants.EnvAzureHSMVaultURL, "stub"),
		framework.MakeEnv(constants.EnvMAAURL, "stub"),
		framework.MakeEnv(constants.EnvAzureClientID, "stub"),
		framework.MakeEnv(constants.EnvAzureTenantID, "stub"),
		framework.MakeEnv(constants.EnvAzureClientSecret, "stub"),
	}...)
	defer cfg.Cleanup()
	cancelCoordinator := f.StartCoordinator(f.Ctx, cfg)

	// set Manifest
	log.Println("Setting the Manifest")
	recoveryData, err := f.SetManifest(f.TestManifest)
	require.NoError(err, "failed to set Manifest")

	// Verify sealed key
	verifySealedKey := func() {
		log.Println("Verifying sealed key")
		sealedKey, err := os.ReadFile(filepath.Join(cfg.SealDir, stdstore.SealedKeyFname))
		require.NoError(err, "failed to read sealed key")
		assert.True(bytes.HasPrefix(sealedKey, keyrelease.HSMSealedPrefix), "sealed key is not HSM sealed")
	}
	verifySealedKey()

	log.Println("Save certificate before we try to recover.")
	cert, _, _, err := api.VerifyCoordinator(f.Ctx, f.ClientServerAddr, api.VerifyOptions{InsecureSkipVerify: true})
	require.NoError(err)

	cancelCoordinator = f.VerifyCertAfterRecovery(cert, cancelCoordinator, cfg)
	verifySealedKey()

	// Perform recovery and verify everything still works as before
	_, _ = f.TriggerRecovery(cfg, cancelCoordinator)
	recoveryKey, err := api.DecryptRecoveryData(recoveryData["testRecKey1"], test.RecoveryPrivateKeyOne)
	require.NoError(err, "Failed to decrypt the recovery data.")

	require.NoError(f.SetRecover(recoveryKey, test.RecoveryPrivateKeyOne))
	t.Log("Performed recovery, now checking status again...")
	statusCode, err := f.GetStatus()
	require.NoError(err)
	assert.EqualValues(int(state.AcceptingMarbles), statusCode, "Server is in wrong status after recovery.")

	verifySealedKey()

	// Update the manifest to disable HSM sealing
	hsmSealingManifest.Config.FeatureGates = nil
	_, _, missing, err := f.SetUpdateManifest(hsmSealingManifest, test.AdminOneCert, test.AdminOnePrivKey)
	require.NoError(err, "failed to update manifest to disable HSM sealing")
	require.Zero(missing, "manifest update incomplete: missing user acknowledgements")

	// Sealed key should now be sealed without HSM key
	log.Println("Verifying sealed key")
	sealedKey, err := os.ReadFile(filepath.Join(cfg.SealDir, stdstore.SealedKeyFname))
	require.NoError(err, "failed to read sealed key")
	assert.False(bytes.HasPrefix(sealedKey, keyrelease.HSMSealedPrefix), "sealed key is still HSM sealed")
}
