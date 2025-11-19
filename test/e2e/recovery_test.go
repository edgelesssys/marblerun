//go:build e2e

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	oss_mnf "github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/test/e2e/manifest"
)

func TestRecoveryWithoutInitialManifest(t *testing.T) {
	t.Parallel()

	t.Log("Starting recovery test")
	ctx, _, require, kubectl, cmd, tmpDir, namespace := setUpTest(t, *replicas)

	// Verify all instances are accepting a manifest
	getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingManifest)

	t.Log("Scaling down to 0 replicas")
	require.NoError(kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, 0))

	t.Log("Deleting Key Encryption Keys")
	require.NoError(kubectl.DeleteConfigMap(ctx, namespace, kekMap))

	t.Logf("Scaling back to %d replicas. Coordinator should be in recovery mode", *replicas)
	require.NoError(kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, *replicas))

	getStatus(ctx, t, kubectl, cmd, namespace, state.Recovery)

	// Write manifest to file
	pub, priv := manifest.GenerateKey(t)
	cert := manifest.GenerateCertificate(t, priv)
	mnf := manifest.DefaultManifest(cert, pub, marbleConfig)
	manifestPath := writeManifest(t, mnf, tmpDir)

	// Set new manifest to remove recovery mode
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
}

func TestBackupAndRestoreInFreshNamespace(t *testing.T) {
	t.Parallel()

	ctx, _, require, kubectl, cmd, tmpDir := createBaseObjects(t)
	t.Log("Starting backup and restore test")

	// Set up initial namespace and deployment
	namespace, releaseName := setUpNamespace(ctx, t, kubectl)
	installChart(ctx, t, namespace, releaseName, *replicas)
	getLogsOnFailure(t, kubectl, namespace)
	getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingManifest)

	// Write manifest to file
	pub, priv := manifest.GenerateKey(t)
	cert := manifest.GenerateCertificate(t, priv)
	mnf := manifest.DefaultManifest(cert, pub, marbleConfig)
	manifestPath := writeManifest(t, mnf, tmpDir)

	// Write user key and cert
	privEncoded, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(err)
	require.NoError(os.WriteFile(filepath.Join(tmpDir, keyFileDefault), pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privEncoded,
	}), 0o644))
	require.NoError(os.WriteFile(filepath.Join(tmpDir, certFileDefault), cert, 0o644))

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

	// Set user-defined secret
	keyName := manifest.DefaultUserSecret
	userDefinedSecrets := map[string]oss_mnf.UserSecret{
		keyName: {Key: []byte("custom secret")},
	}
	setSecret(ctx, t, kubectl, cmd, namespace, tmpDir, certFileDefault, keyFileDefault, userDefinedSecrets)

	t.Log("Backing up state")
	secretData, err := kubectl.GetSecretData(ctx, namespace, stateSecretName)
	require.NoError(err)

	// Set up new namespace
	namespace, releaseName = setUpNamespace(ctx, t, kubectl)

	t.Log("Restoring state")
	require.NoError(kubectl.CreateSecret(ctx, namespace, stateSecretName, secretData))

	// Set up deployment in new namespace
	installChart(ctx, t, namespace, releaseName, *replicas)
	getLogsOnFailure(t, kubectl, namespace)
	getStatus(ctx, t, kubectl, cmd, namespace, state.Recovery)

	// Recover the Coordinator
	recoverCoordinator(ctx, t, kubectl, cmd, manifest.DefaultUser, keyFileDefault, namespace, tmpDir)
	getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)

	t.Log("Verifying user-defined secret has expected value")
	readAndVerifySecret(ctx, t, kubectl, cmd, keyName, namespace, tmpDir, userDefinedSecrets[keyName].Key)
}
