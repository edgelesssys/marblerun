package cmd

import (
	"context"
	"fmt"
	"testing"

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

	deploymentName := "marblerun-coordinator"
	namespace := "marblerun"

	_, _, err := deploymentIsReady(testClient, deploymentName, namespace)
	require.Error(err)

	// create fake deployment with one non ready replica
	// create a fake deployment with 1/1 available replicas
	testDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: deploymentName,
		},
		Status: appsv1.DeploymentStatus{
			Replicas:            1,
			UnavailableReplicas: 1,
		},
	}

	_, err = testClient.AppsV1().Deployments(namespace).Create(context.TODO(), testDeployment, metav1.CreateOptions{})
	require.NoError(err)

	ready, status, err := deploymentIsReady(testClient, deploymentName, namespace)
	require.NoError(err)
	assert.False(ready, "function returned true when deployment was not ready")
	assert.Equal("0/1", status, fmt.Sprintf("Expected 0/1 ready pods but got %s", status))

	testDeployment.Status.UnavailableReplicas = 0
	testDeployment.Status.AvailableReplicas = 1
	_, err = testClient.AppsV1().Deployments(namespace).UpdateStatus(context.TODO(), testDeployment, metav1.UpdateOptions{})
	require.NoError(err)

	ready, status, err = deploymentIsReady(testClient, deploymentName, namespace)
	require.NoError(err)
	assert.True(ready, "function returned false when deployment was ready")
	assert.Equal("1/1", status, fmt.Sprintf("Expected 1/1 ready pods but got %s", status))
}

func TestCheckDeploymentStatus(t *testing.T) {
	require := require.New(t)
	testClient := fake.NewSimpleClientset()

	deploymentName := "marblerun-coordinator"
	namespace := "marblerun"

	// try without any deployments
	err := checkDeploymentStatus(testClient, deploymentName, namespace)
	require.NoError(err)

	// create a fake deployment with 1/1 available replicas
	testDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: deploymentName,
		},
		Status: appsv1.DeploymentStatus{
			Replicas:          1,
			AvailableReplicas: 1,
		},
	}
	_, err = testClient.AppsV1().Deployments(namespace).Create(context.TODO(), testDeployment, metav1.CreateOptions{})
	require.NoError(err)

	err = checkDeploymentStatus(testClient, deploymentName, namespace)
	require.NoError(err)
}

func TestCliCheck(t *testing.T) {
	require := require.New(t)
	testClient := fake.NewSimpleClientset()

	// try without any deployments
	err := cliCheck(testClient)
	require.NoError(err)

	// create a fake deployment with 1/1 available replicas
	testDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "marblerun-coordinator",
		},
		Status: appsv1.DeploymentStatus{
			Replicas:          1,
			AvailableReplicas: 1,
		},
	}
	_, err = testClient.AppsV1().Deployments("marblerun").Create(context.TODO(), testDeployment, metav1.CreateOptions{})
	require.NoError(err)

	err = cliCheck(testClient)
	require.NoError(err)
}
