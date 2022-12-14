// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package injector

import (
	"encoding/json"
	"strings"
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
					"creationTimestamp": null,
					"labels": {
						"name": "testpod",
						"marblerun/marbletype": "test",
						"marblerun/marblecontainer": "marble-test",
						"marblerun/resource-injection": "enabled"
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
						},
						{
							"name": "marble-test",
							"image": "test:image",
							"command": [
								"/bin/bash"
							],
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
	response, err := mutate([]byte(rawJSON), "coordinator-mesh-api.marblerun:2001", "cluster.local", "kubernetes.azure.com/sgx_epc_mem_in_MiB")
	require.NoError(err, "failed to mutate request")

	r := v1.AdmissionReview{}
	require.NoError(json.Unmarshal(response, &r), "failed to unmarshal response with error %s", err)

	assert.Contains(string(r.Response.Patch), `"op":"add","path":"/spec/containers/1/resources","value":{"limits":{"kubernetes.azure.com/sgx_epc_mem_in_MiB":"10"}}`, "applied incorrect resource patch")
	assert.Contains(string(r.Response.Patch), `"name":"EDG_MARBLE_COORDINATOR_ADDR","value":"coordinator-mesh-api.marblerun:2001"`, "failed to apply coordinator env variable patch")
	assert.Contains(string(r.Response.Patch), `"name":"EDG_MARBLE_TYPE","value":"test"`, "failed to apply marble type env variable patch")
	assert.Contains(string(r.Response.Patch), `"name":"EDG_MARBLE_DNS_NAMES","value":"test,test.injectable,test.injectable.svc.cluster.local"`, "failed to apply DNS name env variable patch")
	assert.Contains(string(r.Response.Patch), `"name":"EDG_MARBLE_UUID_FILE"`, "failed to apply marble UUID file env variable patch")
	assert.Contains(string(r.Response.Patch), `"op":"add","path":"/spec/containers/1/volumeMounts"`, "failed to apply volumeMount patch")
	assert.Contains(string(r.Response.Patch), `"op":"add","path":"/spec/volumes"`, "failed to apply volumes patch")
	assert.Contains(string(r.Response.Patch), `"op":"add","path":"/spec/tolerations","value":[{`, "failed to apply tolerations patch")

	assert.NotContains(string(r.Response.Patch), `"path":"/spec/containers/0/env`, "injected env variables into wrong pod")
	assert.NotContains(string(r.Response.Patch), `"path":"/spec/containers/0/volumeMounts`, "injected volume mount into wrong pod")
	assert.Contains(string(r.Response.Patch), `"path":"/spec/containers/0/resources","value":{}}`, "injected resources into the wrong pod")

	// test if patch works without sgx values
	response, err = mutate([]byte(strings.Replace(rawJSON, `"marblerun/resource-injection": "enabled"`, `"marblerun/resource-injection": "disabled"`, -1)), "coordinator-mesh-api.marblerun:2001", "cluster.local", "kubernetes.azure.com/sgx_epc_mem_in_MiB")
	require.NoError(err, "failed to mutate request")
	require.NoError(json.Unmarshal(response, &r), "failed to unmarshal response with error %s", err)
	assert.NotContains(string(r.Response.Patch), `"op":"add","path":"/spec/containers/1/resources","value":{"limits":{"kubernetes.azure.com/sgx_epc_mem_in_MiB":"10"}}`, "patch contained sgx resources, but resources were not supposed to be set")
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
							"resources": {
								"requests": {
									"cpu": 500
								},
								"limits": {
									"cpu": 1000
								}
							},
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

	response, err := mutate([]byte(rawJSON), "coordinator-mesh-api.marblerun:2001", "cluster.local", "kubernetes.azure.com/sgx_epc_mem_in_MiB")
	require.NoError(err, "failed to mutate request")

	r := v1.AdmissionReview{}
	require.NoError(json.Unmarshal(response, &r), "failed to unmarshal response with error %s", err)

	assert.Contains(string(r.Response.Patch), `"op":"add","path":"/spec/containers/0/resources/limits/kubernetes.azure.com~1sgx_epc_mem_in_MiB","value":"10"}`, "applied incorrect resource patch")
	assert.NotContains(string(r.Response.Patch), `"op":"add","path":"/spec/containers/0/env"`, "applied env variable patch when it shouldnt have")
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

	response, err := mutate([]byte(rawJSON), "coordinator-mesh-api.marblerun:2001", "cluster.local", "kubernetes.azure.com/sgx_epc_mem_in_MiB")
	require.NoError(err, "failed to mutate request")

	r := v1.AdmissionReview{}
	require.NoError(json.Unmarshal(response, &r), "failed to unmarshal response with error %s", err)
	assert.False(r.Response.Allowed)
}

func TestErrorsOnInvalid(t *testing.T) {
	require := require.New(t)

	rawJSON := `This should return Error`

	_, err := mutate([]byte(rawJSON), "coordinator-mesh-api.marblerun:2001", "cluster.local", "kubernetes.azure.com/sgx_epc_mem_in_MiB")
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
	_, err := mutate([]byte(rawJSON), "coordinator-mesh-api.marblerun:2001", "cluster.local", "kubernetes.azure.com/sgx_epc_mem_in_MiB")
	require.Error(err, "did not fail when sending invalid request")
}

func TestDoesNotCreateDoubleVolumeMounts(t *testing.T) {
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
					"creationTimestamp": null,
					"labels": {
						"name": "testpod",
						"marblerun/marbletype": "test",
						"marblerun/marblecontainer": "marble-test",
						"marblerun/resource-injection": "enabled"
					}
				},
				"spec": {
					"containers": [
						{
							"name": "marble-test",
							"image": "test:image",
							"command": [
								"/bin/bash"
							],
							"imagePullPolicy": "IfNotPresent",
							"volumeMounts": [
								{
									"mountPath": "/test-uid",
									"name": "test-uid"
								}
							]
						}
					],
					"volumes": [
						{
							"name": "marble-test-uid",
							"volumeSource": {
								"hostPath": {
									"path": "/test-uid"
								}
							}
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

	response, err := mutate([]byte(rawJSON), "coordinator-mesh-api.marblerun:2001", "cluster.local", "kubernetes.azure.com/sgx_epc_mem_in_MiB")
	require.NoError(err)

	r := v1.AdmissionReview{}
	require.NoError(json.Unmarshal(response, &r))
	assert.NotContains(string(r.Response.Patch), `"path":"/spec/containers/0/volumeMounts`)
	assert.NotContains(string(r.Response.Patch), `"op":"add","path":"/spec/volumes"`)
}
