package injector

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/admission/v1"
)

func TestMutatesValidRequest(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	rawJSON := `{
		"apiVersion": "admission.k8s.io/v1",
		"kind": "AdmissionReview",
		"request": {
			"uid": "705ab4f5-6393-11e8-b7cc-42010a800002",
			"namespace": "injectable",
			"operation": "CREATE",
			"object": {
				"kind": "Pod",
				"apiVersion": "v1",
				"metadata": {
					"name": "testpod",
					"namespace": "injectable",
					"creationTimestamp": null,
					"labels": {
						"name": "testpod",
						"marblerun/marbletype": "test"
					}
				},
				"spec": {
					"containers": [
						{
							"name": "testpod",
							"image": "test:image",
							"command": [
								"/bin/bash"
							],
							"terminationMessagePath": "/dev/termination-log",
							"terminationMessagePolicy": "File",
							"imagePullPolicy": "IfNotPresent"
						}
					]
				},
				"status": {}
			},
			"oldObject": null,
			"dryRun": false,
			"options": {
				"kind": "CreateOptions",
				"apiVersion": "meta.k8s.io/v1"
			}
		}
	}`

	// test if patch contains all desired values
	response, err := mutate([]byte(rawJSON), "coordinator-mesh-api.marblerun:25554", "cluster.local", true)
	require.NoError(err, "failed to mutate request")

	r := v1.AdmissionReview{}
	require.NoError(json.Unmarshal(response, &r), "failed to unmarshal response with error %s", err)
	assert.Contains(string(r.Response.Patch), `"op":"add","path":"/spec/containers/0/env","value":[{"name":"EDG_MARBLE_COORDINATOR_ADDR","value":"coordinator-mesh-api.marblerun:25554"}]`, "failed to apply coordinator env variable patch")
	assert.Contains(string(r.Response.Patch), `"op":"add","path":"/spec/containers/0/env/-","value":{"name":"EDG_MARBLE_TYPE","value":"test"}`, "failed to apply marble type env variable patch")
	assert.Contains(string(r.Response.Patch), `"op":"add","path":"/spec/containers/0/env/-","value":{"name":"EDG_MARBLE_DNS_NAMES","value":"test,test.injectable,test.injectable.svc.cluster.local"}`, "failed to apply DNS name env varibale patch")
	assert.Contains(string(r.Response.Patch), `"op":"add","path":"/spec/containers/0/env/-","value":{"name":"EDG_MARBLE_UUID_FILE"`, "failed to apply marble UUID file env variable patch")
	assert.Contains(string(r.Response.Patch), `"op":"add","path":"/spec/containers/0/resources/limits`, "failed to apply resource patch")
	assert.Contains(string(r.Response.Patch), `"op":"add","path":"/spec/containers/0/volumeMounts"`, "failed to apply volumeMount patch")
	assert.Contains(string(r.Response.Patch), `"op":"add","path":"/spec/volumes"`, "failed to apply volumes patch")
	assert.Contains(string(r.Response.Patch), `"op":"add","path":"/spec/tolerations","value":[{"key":"kubernetes.azure.com/sgx_epc_mem_in_MiB"`, "failed to apply tolerations patch")

	// test if patch works without sgx values
	response, err = mutate([]byte(rawJSON), "coordinator-mesh-api.marblerun:25554", "cluster.local", false)
	require.NoError(err, "failed to mutate request")
	require.NoError(json.Unmarshal(response, &r), "failed to unmarshal response with error %s", err)
	assert.NotContains(string(r.Response.Patch), `{"op":"add","path":"/spec/tolerations","value":{"key":"kubernetes.azure.com/sgx_epc_mem_in_MiB"}}`, "patch contained sgx tolerations, but tolerations were not supposed to be set")
}

func TestPreSetValues(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	rawJSON := `{
		"apiVersion": "admission.k8s.io/v1",
		"kind": "AdmissionReview",
		"request": {
			"uid": "705ab4f5-6393-11e8-b7cc-42010a800002",
			"namespace": "injectable",
			"operation": "CREATE",
			"object": {
				"kind": "Pod",
				"apiVersion": "v1",
				"metadata": {
					"name": "testpod",
					"namespace": "injectable",
					"creationTimestamp": null,
					"labels": {
						"name": "testpod",
						"marblerun/marbletype": "test"
					}
				},
				"spec": {
					"containers": [
						{
							"name": "testpod",
							"image": "test:image",
							"command": [
								"/bin/bash"
							],
							"terminationMessagePath": "/dev/termination-log",
							"terminationMessagePolicy": "File",
							"imagePullPolicy": "IfNotPresent",
							"env": [
								{
									"name": "EDG_MARBLE_COORDINATOR_ADDR",
									"value": "coordinator-mesh-api.marblerun:42"
								},
								{
									"name": "EDG_MARBLE_TYPE",
									"value": "different"
								},
								{
									"name": "EDG_MARBLE_DNS_NAMES",
									"value": "different.example.com"
								},
								{
									"name": "EDG_MARBLE_UUID_FILE",
									"value": "012345-678-90"
								}
							]
						}
					]
				},
				"status": {}
			},
			"oldObject": null,
			"dryRun": false,
			"options": {
				"kind": "CreateOptions",
				"apiVersion": "meta.k8s.io/v1"
			}
		}
	}`

	response, err := mutate([]byte(rawJSON), "coordinator-mesh-api.marblerun:25554", "cluster.local", true)
	require.NoError(err, "failed to mutate request")

	r := v1.AdmissionReview{}
	require.NoError(json.Unmarshal(response, &r), "failed to unmarshal response with error %s", err)

	assert.NotContains(string(r.Response.Patch), `"op":"add","path":"/spec/containers/0/env"`, "applied coordinator env variable patch when it shouldnt have")
	assert.NotContains(string(r.Response.Patch), `"op":"add","path":"/spec/containers/0/env/-"`, "applied marble type env variable patch when it shouldnt have")
	assert.NotContains(string(r.Response.Patch), `"op":"add","path":"/spec/containers/0/env/-"`, "applied DNS name env varibale patch when it shouldnt have")
	assert.NotContains(string(r.Response.Patch), `"op":"add","path":"/spec/containers/0/env/-"`, "applied marble UUID file env variable patch when it shouldnt have")
}

func TestRejectsUnsetMarbletype(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	rawJSON := `{
		"apiVersion": "admission.k8s.io/v1",
		"kind": "AdmissionReview",
		"request": {
			"uid": "705ab4f5-6393-11e8-b7cc-42010a800002",
			"namespace": "injectable",
			"operation": "CREATE",
			"object": {
				"kind": "Pod",
				"apiVersion": "v1",
				"metadata": {
					"name": "testpod",
					"namespace": "injectable",
					"creationTimestamp": null,
					"labels": {
						"name": "testpod"
					}
				},
				"spec": {
					"containers": [
						{
							"name": "testpod",
							"image": "test:image",
							"command": [
								"/bin/bash"
							],
							"terminationMessagePath": "/dev/termination-log",
							"terminationMessagePolicy": "File",
							"imagePullPolicy": "IfNotPresent"
						}
					]
				},
				"status": {}
			},
			"oldObject": null,
			"dryRun": false,
			"options": {
				"kind": "CreateOptions",
				"apiVersion": "meta.k8s.io/v1"
			}
		}
	}`

	response, err := mutate([]byte(rawJSON), "coordinator-mesh-api.marblerun:25554", "cluster.local", true)
	require.NoError(err, "failed to mutate request")

	r := v1.AdmissionReview{}
	require.NoError(json.Unmarshal(response, &r), "failed to unmarshal response with error %s", err)

	assert.Equal("Rejected", r.Response.Result.Status, "failed to reject pod on unset marbletype")
}

func TestErrorsOnInvalid(t *testing.T) {
	require := require.New(t)

	rawJSON := `This should return Error`

	_, err := mutate([]byte(rawJSON), "coordinator-mesh-api.marblerun:25554", "cluster.local", true)
	require.Error(err, "did not fail on invalid request")
}

func TestErrorsOnInvalidPod(t *testing.T) {
	require := require.New(t)

	rawJSON := `{
		"apiVersion": "admission.k8s.io/v1",
		"kind": "AdmissionReview",
		"request": {
			"object": "invalid"
		}
	}`
	_, err := mutate([]byte(rawJSON), "coordinator-mesh-api.marblerun:25554", "cluster.local", true)
	require.Error(err, "did not fail when sending invalid request")
}
