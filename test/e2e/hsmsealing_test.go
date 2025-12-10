//go:build hsmsealing && e2e

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/keyrelease"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/edgelesssys/marblerun/test/e2e/helm"
	"github.com/edgelesssys/marblerun/test/e2e/manifest"
)

func TestHSMSealing(t *testing.T) {
	t.Parallel()

	ctx, assert, require, kubectl, cmd, tmpDir := createBaseObjects(t)
	t.Log("Starting test")

	pub, priv := manifest.GenerateKey(t)
	crt := manifest.GenerateCertificate(t, priv)

	privEncoded, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(err)
	require.NoError(os.WriteFile(filepath.Join(tmpDir, keyFileDefault), pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privEncoded,
	}), 0o644))
	require.NoError(os.WriteFile(filepath.Join(tmpDir, publicKeyFileDefault), pub, 0o644))
	require.NoError(os.WriteFile(filepath.Join(tmpDir, certFileDefault), crt, 0o644))

	mnf := manifest.DefaultManifest(crt, pub, marbleConfig)
	manifestPath := writeManifest(t, mnf, tmpDir)

	namespace, releaseName := setUpNamespace(ctx, t, kubectl)

	helm, err := helm.New(t, *kubeConfigPath, namespace)
	require.NoError(err)
	t.Logf("Installing chart %q from %q", namespace, *chartPath)
	uninstall, err := helm.InstallChart(ctx, releaseName, namespace, *chartPath, *replicas, defaultTimeout, nil)
	require.NoError(err)
	t.Cleanup(uninstall)
	getLogsOnFailure(t, kubectl, namespace)

	// Verify all instances are accepting a manifest
	getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingManifest)

	// Set manifest for any Coordinator instance
	t.Log("Setting manifest")
	withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
		_, err := cmd.Run(
			ctx,
			"manifest", "set",
			manifestPath, net.JoinHostPort(localhost, port),
			"--recoverydata", filepath.Join(tmpDir, recoveryDataFile),
			"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
			eraConfig,
		)
		return err
	})
	t.Log("Manifest set")

	// Verify all instances are accepting marbles
	getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)

	t.Log("Verifying sealed key")
	sealedState, err := kubectl.GetSecretData(ctx, namespace, stateSecretName)
	require.NoError(err)
	assert.True(bytes.HasPrefix(sealedState[stdstore.SealedKeyFname], keyrelease.HSMSealedPrefix), "sealed key is not HSM sealed")

	t.Log("Scaling down Coordinator deployment to 0")
	require.NoError(kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, 0))
	t.Log("Deleting Key Encryption Keys")
	require.NoError(kubectl.DeleteConfigMap(ctx, namespace, kekMap))

	t.Log("Scaling up Coordinator deployment to 1")
	require.NoError(kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, 1))
	getStatus(ctx, t, kubectl, cmd, namespace, state.Recovery)

	recoverCoordinator(ctx, t, kubectl, cmd, manifest.DefaultUser, keyFileDefault, namespace, tmpDir)
	getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)

	t.Logf("Scaling up Coordinator deployment to %d", *replicas)
	require.NoError(kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, *replicas))

	getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)

	t.Log("Verifying sealed key")
	sealedState, err = kubectl.GetSecretData(ctx, namespace, stateSecretName)
	require.NoError(err)
	assert.True(bytes.HasPrefix(sealedState[stdstore.SealedKeyFname], keyrelease.HSMSealedPrefix), "sealed key is not HSM sealed")

	expectedMnf, err := os.ReadFile(filepath.Join(tmpDir, manifestFile))
	require.NoError(err)
	actualMnfFile := filepath.Join(tmpDir, "current.json")

	forAllPods(ctx, t, kubectl, namespace, func(pod, port string) error {
		t.Logf("Checking manifest on %q", pod)
		if _, err := cmd.Run(
			ctx,
			"manifest", "get",
			net.JoinHostPort(localhost, port),
			"--output", actualMnfFile,
			eraConfig,
		); err != nil {
			return err
		}

		actualMnf, err := os.ReadFile(actualMnfFile)
		require.NoError(err)
		assert.Equal(expectedMnf, actualMnf)
		return nil
	})

	// Regression: verify that recovery data hasn't been lost
	secretData, err := kubectl.GetSecretData(ctx, namespace, stateSecretName)
	require.NoError(err)
	sealedData := secretData[stdstore.SealedDataFname]
	recoveryDataLen := binary.LittleEndian.Uint32(sealedData[:4])
	require.Greater(recoveryDataLen, uint32(0))

	// Disable HSM sealing
	t.Log("Updating manifest to disable HSM sealing")
	mnf = manifest.DefaultManifest(crt, pub, marbleConfig)
	mnf.Config.FeatureGates = nil
	updateMnf, err := json.Marshal(mnf)
	require.NoError(err)
	updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, updateMnf, certFileDefault, keyFileDefault)

	t.Log("Verifying sealed key")
	sealedState, err = kubectl.GetSecretData(ctx, namespace, stateSecretName)
	require.NoError(err)
	assert.False(bytes.HasPrefix(sealedState[stdstore.SealedKeyFname], keyrelease.HSMSealedPrefix), "sealed key is still HSM sealed")

	// Verify all instances have the update applied
	// This forces each instance to re-load the state from disk
	forAllPods(ctx, t, kubectl, namespace, func(pod, port string) error {
		t.Logf("Checking manifest on %q", pod)
		if _, err := cmd.Run(
			ctx,
			"manifest", "get",
			net.JoinHostPort(localhost, port),
			"--output", actualMnfFile,
			eraConfig,
		); err != nil {
			return err
		}

		actualMnf, err := os.ReadFile(actualMnfFile)
		require.NoError(err)
		assert.Equal(updateMnf, actualMnf)
		return nil
	})

	t.Log("Verifying sealed key")
	sealedState, err = kubectl.GetSecretData(ctx, namespace, stateSecretName)
	require.NoError(err)
	assert.False(bytes.HasPrefix(sealedState[stdstore.SealedKeyFname], keyrelease.HSMSealedPrefix), "sealed key is still HSM sealed")

	// Apply an update to each instance
	// This forces each instance to individually re-seal the key
	forAllPods(ctx, t, kubectl, namespace, func(pod, port string) error {
		defaultPackage := mnf.Packages[manifest.DefaultMarble]
		defaultPackage.SecurityVersion++
		mnf.Packages[manifest.DefaultMarble] = defaultPackage
		updateMnf, err := json.Marshal(mnf)
		require.NoError(err)
		updateMnfPath := filepath.Join(tmpDir, "update.json")
		require.NoError(os.WriteFile(updateMnfPath, updateMnf, 0o644))

		_, err = cmd.Run(
			ctx,
			"manifest", "update", "apply",
			updateMnfPath, net.JoinHostPort(localhost, port),
			"--key", filepath.Join(tmpDir, keyFileDefault),
			"--cert", filepath.Join(tmpDir, certFileDefault),
			"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
			eraConfig,
		)
		return err
	})

	t.Log("Verifying sealed key")
	sealedState, err = kubectl.GetSecretData(ctx, namespace, stateSecretName)
	require.NoError(err)
	assert.False(bytes.HasPrefix(sealedState[stdstore.SealedKeyFname], keyrelease.HSMSealedPrefix), "sealed key is still HSM sealed")
}
