// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/edgelesssys/marblerun/cli/internal/helm"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDeploymentIsReady(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	testClient := fake.NewSimpleClientset()
	ctx := context.Background()

	_, _, err := deploymentIsReady(ctx, testClient, helm.CoordinatorDeployment, helm.Namespace)
	require.Error(err)

	// create fake deployment with one non ready replica
	// create a fake deployment with 1/1 available replicas
	testDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: helm.CoordinatorDeployment,
		},
		Status: appsv1.DeploymentStatus{
			Replicas:            1,
			UnavailableReplicas: 1,
		},
	}

	_, err = testClient.AppsV1().Deployments(helm.Namespace).Create(ctx, testDeployment, metav1.CreateOptions{})
	require.NoError(err)

	ready, status, err := deploymentIsReady(ctx, testClient, helm.CoordinatorDeployment, helm.Namespace)
	require.NoError(err)
	assert.False(ready, "function returned true when deployment was not ready")
	assert.Equal("0/1", status, fmt.Sprintf("expected 0/1 ready pods but got %s", status))

	testDeployment.Status.UnavailableReplicas = 0
	testDeployment.Status.AvailableReplicas = 1
	_, err = testClient.AppsV1().Deployments(helm.Namespace).UpdateStatus(ctx, testDeployment, metav1.UpdateOptions{})
	require.NoError(err)

	ready, status, err = deploymentIsReady(ctx, testClient, helm.CoordinatorDeployment, helm.Namespace)
	require.NoError(err)
	assert.True(ready, "function returned false when deployment was ready")
	assert.Equal("1/1", status, fmt.Sprintf("expected 1/1 ready pods but got %s", status))
}

func TestCheckDeploymentStatus(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	testClient := fake.NewSimpleClientset()
	ctx := context.Background()
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)

	// try without any deployments
	err := checkDeploymentStatus(cmd, testClient, helm.CoordinatorDeployment, helm.Namespace, 10)
	assert.NoError(err)

	// create a fake deployment with 1/1 available replicas
	testDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: helm.CoordinatorDeployment,
		},
		Status: appsv1.DeploymentStatus{
			Replicas:          1,
			AvailableReplicas: 1,
		},
	}
	_, err = testClient.AppsV1().Deployments(helm.Namespace).Create(ctx, testDeployment, metav1.CreateOptions{})
	require.NoError(err)

	err = checkDeploymentStatus(cmd, testClient, helm.CoordinatorDeployment, helm.Namespace, 10)
	assert.NoError(err)
}

func TestCliCheck(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	testClient := fake.NewSimpleClientset()
	ctx := context.Background()
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)

	// try without any deployments
	err := cliCheck(cmd, testClient, 10)
	assert.NoError(err)

	// create a fake deployment with 1/1 available replicas
	testDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: helm.CoordinatorDeployment,
		},
		Status: appsv1.DeploymentStatus{
			Replicas:          1,
			AvailableReplicas: 1,
		},
	}
	_, err = testClient.AppsV1().Deployments(helm.Namespace).Create(ctx, testDeployment, metav1.CreateOptions{})
	require.NoError(err)

	err = cliCheck(cmd, testClient, 10)
	assert.NoError(err)

	err = testClient.AppsV1().Deployments(helm.Namespace).Delete(ctx, helm.CoordinatorDeployment, metav1.DeleteOptions{})
	require.NoError(err)

	timeoutDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: helm.CoordinatorDeployment,
		},
		Status: appsv1.DeploymentStatus{
			Replicas:            1,
			UnavailableReplicas: 0,
		},
	}
	_, err = testClient.AppsV1().Deployments(helm.Namespace).Create(ctx, timeoutDeployment, metav1.CreateOptions{})
	require.NoError(err)

	err = cliCheck(cmd, testClient, 2)
	assert.Error(err)
}
