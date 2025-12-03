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
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/constants"
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
	mnf.Config.FeatureGates = append(mnf.Config.FeatureGates, "AzureHSMSealing")
	manifestPath := writeManifest(t, mnf, tmpDir)

	namespace, releaseName := setUpNamespace(ctx, t, kubectl)

	helm, err := helm.New(t, *kubeConfigPath, namespace)
	require.NoError(err)
	t.Logf("Installing chart %q from %q", namespace, *chartPath)
	extraVals := map[string]any{
		"coordinator": map[string]any{
			"hsm": map[string]any{
				"keyName":    os.Getenv(constants.EnvHSMKeyName),
				"keyVersion": os.Getenv(constants.EnvHSMKeyVersion),
				"vaultURL":   os.Getenv(constants.EnvHSMVaultURL),
				"maaURL":     os.Getenv(constants.EnvMAAURL),
			},
			"azureCredentials": map[string]any{
				"clientID":     os.Getenv(constants.EnvAzureClientID),
				"tenantID":     os.Getenv(constants.EnvAzureTenantID),
				"clientSecret": os.Getenv(constants.EnvAzureClientSecret),
			},
		},
	}
	uninstall, err := helm.InstallChart(ctx, releaseName, namespace, *chartPath, *replicas, defaultTimeout, extraVals)
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
	assert.Truef(bytes.HasPrefix(sealedState[stdstore.SealedKeyFname], keyrelease.HSMSealedPrefix), "sealed key is not HSM sealed")

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
	assert.Truef(bytes.HasPrefix(sealedState[stdstore.SealedKeyFname], keyrelease.HSMSealedPrefix), "sealed key is not HSM sealed")

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
}
