//go:build e2e

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	oss_mnf "github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/test/e2e/helm"
	"github.com/edgelesssys/marblerun/test/e2e/manifest"
)

func TestChartUpdate(t *testing.T) {
	if *oldChartPath == "" {
		t.Skip("No chart path provided to upgrade from. Skipping...")
	}

	t.Parallel()

	ctx, assert, require, kubectl, cmd, tmpDir := createBaseObjects(t)
	namespace, releaseName := setUpNamespace(ctx, t, kubectl)
	getLogsOnFailure(t, kubectl, namespace)

	helm, err := helm.New(t, *kubeConfigPath, namespace)
	require.NoError(err)
	t.Logf("Installing chart %q from %q", releaseName, *oldChartPath)
	uninstall, err := helm.InstallChart(ctx, releaseName, namespace, *oldChartPath, *replicas, defaultTimeout, nil)
	require.NoError(err)
	t.Cleanup(uninstall)

	pub, priv := manifest.GenerateKey(t)
	crt := manifest.GenerateCertificate(t, priv)

	mnf := manifest.DefaultManifest(crt, pub, marbleConfig)

	marble := mnf.Marbles[manifest.DefaultMarble]
	marbleSecretFile := "/test-secret"
	previousMarbleSecretFile := marbleSecretFile + ".previous"
	marble.Parameters.Argv = []string{"marble", "secrets", marbleSecretFile, previousMarbleSecretFile}
	marble.Parameters.Files[marbleSecretFile] = oss_mnf.File{
		Data:     "{{ raw .Secrets.ProtectedFilesKey }}",
		Encoding: "string",
	}
	marble.Parameters.Files[previousMarbleSecretFile] = oss_mnf.File{
		Data:     "{{ raw .Previous.Secrets.ProtectedFilesKey }}",
		Encoding: "string",
	}
	mnf.Marbles[manifest.DefaultMarble] = marble

	manifestPath := writeManifest(t, mnf, tmpDir)
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

	var symmetricKey []byte

	// Set up one HTTP client to use for requests to both the old and new versions of the Coordinator
	// The new Coordinator instances should successfully reuse the HTTP certificates set up by the old instances
	coordinatorCertChain, err := os.ReadFile(filepath.Join(tmpDir, coordinatorCertFileDefault))
	require.NoError(err)
	caPool := x509.NewCertPool()
	require.True(caPool.AppendCertsFromPEM(coordinatorCertChain), "failed loading coordinator cert chain")
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
		},
	}

	t.Logf("Starting Marble Pod %s in namespace %s", manifest.DefaultMarble, namespace)
	podName, err := createMarblePod(ctx, kubectl, namespace, manifest.DefaultMarble, nil, nil)
	require.NoError(err)

	t.Logf("Checking Marble Pod %s in namespace %s", manifest.DefaultMarble, namespace)
	withPortForward(ctx, t, kubectl, namespace, podName, marbleClientPort, func(port string) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s:%s", localhost, port), nil)
		if err != nil {
			return err
		}

		resp, err := client.Do(req)
		if resp != nil {
			defer resp.Body.Close()
		}
		if err != nil {
			return err
		}
		if http.StatusOK != resp.StatusCode {
			return fmt.Errorf("http.Get returned: %s", resp.Status)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		marbleSecrets := make(map[string][]byte)
		if err := json.Unmarshal(body, &marbleSecrets); err != nil {
			return fmt.Errorf("failed to unmarshal response '%s': %w", body, err)
		}
		if len(marbleSecrets) != 2 {
			return fmt.Errorf("expected one secret from Marble, got %d", len(marbleSecrets))
		}
		symmetricKey = marbleSecrets[marbleSecretFile]
		assert.Equal(symmetricKey, marbleSecrets[previousMarbleSecretFile])
		return nil

	})
	t.Logf("Deleting Marble Pod %s in namespace %s", manifest.DefaultMarble, namespace)
	assert.NoError(kubectl.DeletePod(ctx, namespace, podName))

	// Now upgrade the chart (and Coordinator image) and verify secrets were properly preserved by the Coordinator
	t.Logf("Upgrading chart %q in namespace %q from %q", releaseName, namespace, *chartPath)
	require.NoError(helm.UpgradeChart(ctx, releaseName, *chartPath, namespace, defaultTimeout, nil))
	getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)

	t.Logf("Starting Marble Pod %s in namespace %s", manifest.DefaultMarble, namespace)
	podName, err = createMarblePod(ctx, kubectl, namespace, manifest.DefaultMarble, nil, nil)
	require.NoError(err)

	t.Logf("Checking Marble Pod %s in namespace %s", manifest.DefaultMarble, namespace)
	withPortForward(ctx, t, kubectl, namespace, podName, marbleClientPort, func(port string) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s:%s", localhost, port), nil)
		if err != nil {
			return err
		}

		resp, err := client.Do(req)
		if resp != nil {
			defer resp.Body.Close()
		}
		if err != nil {
			return err
		}
		if http.StatusOK != resp.StatusCode {
			return fmt.Errorf("http.Get returned: %s", resp.Status)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		marbleSecrets := make(map[string][]byte)
		if err := json.Unmarshal(body, &marbleSecrets); err != nil {
			return fmt.Errorf("failed to unmarshal response '%s': %w", body, err)
		}
		if len(marbleSecrets) != 2 {
			return fmt.Errorf("expected one secret from Marble, got %d", len(marbleSecrets))
		}

		// Assert the secret wasn't changed by the Coordinator upgrade
		assert.Equal(symmetricKey, marbleSecrets[marbleSecretFile])
		assert.Equal(symmetricKey, marbleSecrets[previousMarbleSecretFile])
		return nil

	})

	t.Logf("Deleting Marble Pod %s in namespace %s", manifest.DefaultMarble, namespace)
	assert.NoError(kubectl.DeletePod(ctx, namespace, podName))
}
