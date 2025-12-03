//go:build hsmsealing && e2e

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/test/e2e/cmd"
	"github.com/edgelesssys/marblerun/test/e2e/helm"
	"github.com/edgelesssys/marblerun/test/e2e/kubectl"
	"github.com/edgelesssys/marblerun/test/e2e/manifest"
	"github.com/stretchr/testify/require"
)

func setManifest(
	ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd,
	tmpDir string, mnf manifest.Manifest, replicas int,
) string {
	// When built with "hsmsealing" tag, always append the feature gate
	mnf.Config.FeatureGates = append(mnf.Config.FeatureGates, "AzureHSMSealing")

	namespace, releaseName := setUpNamespace(ctx, t, kubectl)
	manifestPath := writeManifest(t, mnf, tmpDir)
	installChart(ctx, t, namespace, releaseName, replicas)

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

	return namespace
}

func installChart(ctx context.Context, t *testing.T, namespace, releaseName string, replicas int) {
	t.Helper()
	require := require.New(t)

	// Provide HSM sealing configuration via Helm chart values
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

	helm, err := helm.New(t, *kubeConfigPath, namespace)
	require.NoError(err)
	t.Logf("Installing chart %q from %q", releaseName, *chartPath)
	uninstall, err := helm.InstallChart(ctx, releaseName, namespace, *chartPath, replicas, defaultTimeout, extraVals)
	require.NoError(err)
	t.Cleanup(uninstall)
}
