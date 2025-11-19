//go:build e2e

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/test/e2e/manifest"
)

func TestSetManifest(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		manifest manifest.Manifest
		replicas int
	}{
		"simple": {
			manifest: func() manifest.Manifest {
				pub, priv := manifest.GenerateKey(t)
				cert := manifest.GenerateCertificate(t, priv)
				m := manifest.DefaultManifest(cert, pub, marbleConfig)
				return m
			}(),
			replicas: 1,
		},
		"3 replicas": {
			manifest: func() manifest.Manifest {
				pub, priv := manifest.GenerateKey(t)
				cert := manifest.GenerateCertificate(t, priv)
				m := manifest.DefaultManifest(cert, pub, marbleConfig)
				return m
			}(),
			replicas: 3,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx, _, _, kubectl, cmd, tmpDir := createBaseObjects(t)
			t.Log("Starting manifest test")
			namespace := setManifest(ctx, t, kubectl, cmd, tmpDir, tc.manifest, tc.replicas)
			getLogsOnFailure(t, kubectl, namespace)

			// Setting the manifest should now fail for all instances
			forAllPods(ctx, t, kubectl, namespace, func(_, port string) error {
				_, err := cmd.Run(
					ctx, "manifest", "set",
					filepath.Join(tmpDir, manifestFile), net.JoinHostPort(localhost, port),
					"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault+".failed"),
					eraConfig,
				)
				if !strings.Contains(err.Error(), "server is not in expected state") {
					return fmt.Errorf("expected server not in expected state error: %q", err.Error())
				}
				return nil
			})

			t.Log("Test complete")
		})
	}
}

func TestSetManifestConcurrent(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		manifest manifest.Manifest
	}{
		"default manifest": {
			manifest: func() manifest.Manifest {
				pub, priv := manifest.GenerateKey(t)
				cert := manifest.GenerateCertificate(t, priv)
				m := manifest.DefaultManifest(cert, pub, marbleConfig)
				return m
			}(),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Log("Starting manifest test")
			ctx, assert, require, kubectl, cmd, tmpDir, namespace := setUpTest(t, *replicas)
			manifestPath := writeManifest(t, tc.manifest, tmpDir)

			// Verify all instances are accepting a manifest
			getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingManifest)

			coordinatorPods, err := kubectl.GetAvailablePodNamesForService(ctx, namespace, coordinatorClientService)
			require.NoError(err)

			// Run concurrent manifest set
			var setErrs int
			var setErrsMu sync.Mutex
			var wg sync.WaitGroup
			wg.Add(*replicas)
			for _, pod := range coordinatorPods {
				podName := pod
				go func() {
					defer wg.Done()
					t.Logf("Setting manifest for pod %q", podName)

					port, cancel, err := kubectl.PortForwardPod(ctx, namespace, podName, coordinatorClientPort)
					require.NoError(err)
					defer cancel()

					_, err = cmd.Run(
						ctx, "manifest", "set",
						manifestPath, net.JoinHostPort(localhost, port),
						"--coordinator-cert", filepath.Join(tmpDir, fmt.Sprintf("%s.%s", podName, coordinatorCertFileDefault)),
						eraConfig,
					)

					setErrsMu.Lock()
					if err != nil {
						setErrs++
					}
					setErrsMu.Unlock()
				}()
			}

			wg.Wait()
			assert.Equal(*replicas-1, setErrs, "Expected only one manifest set to succeed")

			getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)

			t.Log("Test complete")
		})
	}
}
