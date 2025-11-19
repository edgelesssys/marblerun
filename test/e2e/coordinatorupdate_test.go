//go:build e2e

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/test/e2e/manifest"
)

func TestDeployUpdatedCoordinatorOnNewNode(t *testing.T) {
	// For this test, the update image should have a higher security version than the current image. This should trigger
	// the case where attestation fails when getting the encryption key because of the security version mismatch.

	t.Parallel()

	// Begin with 0 replicas
	ctx, _, require, kubectl, cmd, tmpDir, namespace := setUpTest(t, 0)

	// Derive update image name from current image name
	imageName, err := kubectl.GetDeploymentImage(ctx, namespace, coordinatorDeployment, coordinatorContainerName)
	require.NoError(err)
	updateImageName := getCoordinatorUpdateImage(t, imageName)

	// Prepare second deployment
	const coordinatorDeployment2 = coordinatorDeployment + "2"
	require.NoError(kubectl.CloneDeployment(ctx, namespace, coordinatorDeployment, coordinatorDeployment2, coordinatorDeploymentSelectorLabel))
	require.NoError(kubectl.SetDeploymentImage(ctx, namespace, coordinatorDeployment2, coordinatorContainerName, updateImageName))

	// Choose two different SGX nodes to assign the deployments to
	nodes, err := kubectl.GetSGXNodes(ctx)
	require.NoError(err)
	var node1, node2 string
	switch len(nodes) {
	case 0:
		t.Log("Failed to detect SGX nodes. Continuing without node assignment.")
		markAsSkippedIfPasses(t)
	case 1:
		t.Log("Only one SGX node detected. Assigning both deployments to this node.")
		markAsSkippedIfPasses(t)
		node1 = nodes[0]
		node2 = nodes[0]
	default:
		node1 = nodes[0]
		node2 = nodes[1]
	}
	require.NoError(kubectl.AssignDeploymentToNode(ctx, namespace, coordinatorDeployment, node1))
	require.NoError(kubectl.AssignDeploymentToNode(ctx, namespace, coordinatorDeployment2, node2))

	// Scale deployment 1 to 1 replica and set manifest
	{
		t.Log("Scaling deployment 1 to 1 replica")
		require.NoError(kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, 1))
		coordinatorPods, err := kubectl.GetAvailablePodNamesForDeployment(ctx, namespace, coordinatorDeployment)
		require.NoError(err)
		require.Len(coordinatorPods, 1)
		podName := coordinatorPods[0]

		withPortForward(ctx, t, kubectl, namespace, podName, coordinatorClientPort, func(port string) error {
			return getStatusOfInstance(ctx, t, cmd, port, state.AcceptingManifest)
		})

		// Write manifest to file
		pub, priv := manifest.GenerateKey(t)
		cert := manifest.GenerateCertificate(t, priv)
		mnf := manifest.DefaultManifest(cert, pub, marbleConfig)
		manifestPath := writeManifest(t, mnf, tmpDir)

		t.Log("Setting manifest")
		withPortForward(ctx, t, kubectl, namespace, podName, coordinatorClientPort, func(port string) error {
			_, err := cmd.Run(
				ctx,
				"manifest", "set",
				manifestPath, net.JoinHostPort(localhost, port),
				"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
				eraConfig,
			)
			return err
		})
		t.Log("Manifest set")

		withPortForward(ctx, t, kubectl, namespace, podName, coordinatorClientPort, func(port string) error {
			return getStatusOfInstance(ctx, t, cmd, port, state.AcceptingMarbles)
		})
	}

	// Scale deployment 2 to 1 replica and update image of deployment 1
	{
		t.Log("Scaling deployment 2 to 1 replica")
		require.NoError(kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment2, 1))
		coordinatorPods, err := kubectl.GetAvailablePodNamesForDeployment(ctx, namespace, coordinatorDeployment2)
		require.NoError(err)
		require.Len(coordinatorPods, 1)
		podName := coordinatorPods[0]

		withPortForward(ctx, t, kubectl, namespace, podName, coordinatorClientPort, func(port string) error {
			status, err := cmd.GetStatus(ctx, net.JoinHostPort(localhost, port), eraConfig)
			if err != nil {
				return err
			}
			t.Logf("Status of %v: %v", podName, status)
			return nil
		})

		t.Log("Updating image of deployment 1")
		require.NoError(kubectl.SetDeploymentImage(ctx, namespace, coordinatorDeployment, coordinatorContainerName, updateImageName))

		t.Log("Verifying state of instance 1")
		getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles) // Uses a service that only targets deployment 1

		// Now that both Coordinators have the same security version, the second Coordinator
		// should be able to get the encryption key from the first Coordinator.
		t.Log("Verifying state of instance 2")
		withPortForward(ctx, t, kubectl, namespace, podName, coordinatorClientPort, func(port string) error {
			return getStatusOfInstance(ctx, t, cmd, port, state.AcceptingMarbles)
		})
	}
}
