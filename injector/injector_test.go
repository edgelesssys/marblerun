/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package injector

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/edgelesssys/marblerun/util/k8sutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	v1 "k8s.io/api/admission/v1"
)

func TestMutate(t *testing.T) {
	defaultRequest := `{
		"apiVersion": "admission.k8s.io/v1",
		"kind": "AdmissionReview",
		"request": {
			"namespace": "injectable",
			"operation": "CREATE",
			"object": {
				"kind": "Pod",
				"apiVersion": "v1",
				"metadata": {
					"name": "testpod",
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
							]
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
				}
			}
		}
	}`

	testCases := map[string]struct {
		rawRequest  string
		resourceKey string
		wantError   bool
		assertions  func(assert *assert.Assertions, response *v1.AdmissionResponse)
	}{
		"mutates valid request": {
			rawRequest:  defaultRequest,
			resourceKey: k8sutil.AzureEpc.String(),
			assertions: func(assert *assert.Assertions, response *v1.AdmissionResponse) {
				assert.Contains(string(response.Patch), `"op":"add","path":"/spec/containers/1/resources","value":{"limits":{"kubernetes.azure.com/sgx_epc_mem_in_MiB":"10"}}`, "applied incorrect resource patch")
				assert.Contains(string(response.Patch), `"name":"EDG_MARBLE_COORDINATOR_ADDR","value":"coordinator-mesh-api.marblerun:2001"`, "failed to apply coordinator env variable patch")
				assert.Contains(string(response.Patch), `"name":"EDG_MARBLE_TYPE","value":"test"`, "failed to apply marble type env variable patch")
				assert.Contains(string(response.Patch), `"name":"EDG_MARBLE_DNS_NAMES","value":"test,test.injectable,test.injectable.svc.cluster.local"`, "failed to apply DNS name env variable patch")
				assert.Contains(string(response.Patch), `"name":"EDG_MARBLE_UUID_FILE"`, "failed to apply marble UUID file env variable patch")
				assert.Contains(string(response.Patch), `"op":"add","path":"/spec/containers/1/volumeMounts"`, "failed to apply volumeMount patch")
				assert.Contains(string(response.Patch), `"op":"add","path":"/spec/volumes"`, "failed to apply volumes patch")
				assert.Contains(string(response.Patch), `"op":"add","path":"/spec/tolerations","value":[{`, "failed to apply tolerations patch")
				assert.NotContains(string(response.Patch), `"path":"/spec/containers/0/env`, "injected env variables into wrong pod")
				assert.NotContains(string(response.Patch), `"path":"/spec/containers/0/volumeMounts`, "injected volume mount into wrong pod")
				assert.Contains(string(response.Patch), `"path":"/spec/containers/0/resources","value":{}}`, "injected resources into the wrong pod")
			},
		},
		"resource injection can be disabled": {
			rawRequest:  strings.ReplaceAll(defaultRequest, `"marblerun/resource-injection": "enabled"`, `"marblerun/resource-injection": "disabled"`),
			resourceKey: k8sutil.AzureEpc.String(),
			assertions: func(assert *assert.Assertions, response *v1.AdmissionResponse) {
				assert.NotContains(
					string(response.Patch),
					`"op":"add","path":"/spec/containers/1/resources","value":{"limits":{"kubernetes.azure.com/sgx_epc_mem_in_MiB":"10"}}`,
					"patch contained sgx resources, but resources were not supposed to be set",
				)
			},
		},
		"sgx resources are appended to existing resources - azure-plugin": {
			rawRequest: `{
				"apiVersion": "admission.k8s.io/v1",
				"kind": "AdmissionReview",
				"request": {
					"namespace": "injectable","operation": "CREATE",
					"object": {
						"kind":"Pod","apiVersion":"v1","metadata":{"name":"testpod","namespace":"injectable","labels":{"name":"testpod","marblerun/marbletype":"test"}},
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
									}
								}
				]}}}}`,
			resourceKey: k8sutil.AzureEpc.String(),
			assertions: func(assert *assert.Assertions, response *v1.AdmissionResponse) {
				assert.Contains(
					string(response.Patch),
					`"op":"add","path":"/spec/containers/0/resources/limits/kubernetes.azure.com~1sgx_epc_mem_in_MiB","value":"10"}`,
					"applied incorrect resource patch",
				)
			},
		},
		"sgx resources are appended to existing resources - intel-plugin": {
			rawRequest: `{
				"apiVersion": "admission.k8s.io/v1",
				"kind": "AdmissionReview",
				"request": {
					"namespace": "injectable","operation": "CREATE",
					"object": {
						"kind":"Pod","apiVersion":"v1","metadata":{"name":"testpod","namespace":"injectable","labels":{"name":"testpod","marblerun/marbletype":"test"}},
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
									}
								}
			]}}}}`,
			resourceKey: k8sutil.IntelEpc.String(),
			assertions: func(assert *assert.Assertions, response *v1.AdmissionResponse) {
				assert.Contains(string(response.Patch), `"op":"add","path":"/spec/containers/0/resources/limits/sgx.intel.com~1epc","value":"10Mi"}`, "applied incorrect epc patch")
				assert.Contains(string(response.Patch), `"op":"add","path":"/spec/containers/0/resources/limits/sgx.intel.com~1enclave","value":"1"}`, "applied incorrect enclave patch")
				assert.Contains(string(response.Patch), `"op":"add","path":"/spec/containers/0/resources/limits/sgx.intel.com~1provision","value":"1"}`, "applied incorrect provision patch")
			},
		},
		"env variables are ignored if already set": {
			rawRequest: `{
				"apiVersion": "admission.k8s.io/v1",
				"kind": "AdmissionReview",
				"request": {
					"namespace": "injectable","operation": "CREATE",
					"object": {
						"kind":"Pod","apiVersion":"v1","metadata":{"name":"testpod","namespace":"injectable","labels":{"name":"testpod","marblerun/marbletype":"test"}},
						"spec": {
							"containers": [
								{
									"name": "testpod",
									"image": "test:image",
									"command": [
										"/bin/bash"
									],
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
			]}}}}`,
			resourceKey: k8sutil.AzureEpc.String(),
			assertions: func(assert *assert.Assertions, response *v1.AdmissionResponse) {
				assert.NotContains(string(response.Patch), `"op":"add","path":"/spec/containers/0/env"`, "applied env variable patch when it shouldn't have")
			},
		},
		"uuid mounts are added to existing mounts": {
			rawRequest: `{
				"apiVersion": "admission.k8s.io/v1",
				"kind": "AdmissionReview",
				"request": {
					"namespace":"injectable","operation":"CREATE",
					"object": {
						"kind":"Pod","apiVersion":"v1",
						"metadata":{
							"name":"testpod",
							"labels":{"name":"testpod","marblerun/marbletype":"test","marblerun/marblecontainer":"marble-test","marblerun/resource-injection":"enabled"}
						},
						"spec": {
							"containers": [
								{
									"name":"marble-test","image":"test:image","command":["/bin/bash"],
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
			}}}}`,
			resourceKey: k8sutil.AzureEpc.String(),
			assertions: func(assert *assert.Assertions, response *v1.AdmissionResponse) {
				assert.NotContains(string(response.Patch), `"path":"/spec/containers/0/volumeMounts`)
				assert.NotContains(string(response.Patch), `"op":"add","path":"/spec/volumes"`)
			},
		},
		"requests with unset marbletype are rejected": {
			rawRequest: `{
				"apiVersion": "admission.k8s.io/v1",
				"kind": "AdmissionReview",
				"request": {
					"namespace": "injectable","operation": "CREATE",
					"object": {
						"kind": "Pod","apiVersion": "v1",
						"metadata": {
							"name": "testpod","namespace": "injectable",
							"labels": {"name": "testpod"}
						},
						"spec": {"containers": [{"name": "testpod","image": "test:image","command": ["/bin/bash"]}]}
			}}}`,
			resourceKey: k8sutil.AzureEpc.String(),
			assertions: func(assert *assert.Assertions, response *v1.AdmissionResponse) {
				assert.False(response.Allowed)
			},
		},
		"errors on invalid request": {
			rawRequest:  `This should return Error`,
			resourceKey: k8sutil.AzureEpc.String(),
			wantError:   true,
		},
		"errors on invalid Pod spec": {
			rawRequest: `{
				"apiVersion": "admission.k8s.io/v1",
				"kind": "AdmissionReview",
				"request": {
					"object": "invalid"
				}
			}`,
			resourceKey: k8sutil.AzureEpc.String(),
			wantError:   true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)

			m := New("coordinator-mesh-api.marblerun:2001", "cluster.local", tc.resourceKey, zaptest.NewLogger(t))
			response, err := m.mutate([]byte(tc.rawRequest))
			if tc.wantError {
				require.Error(err)
				return
			}

			assert.NoError(err)
			r := v1.AdmissionReview{}
			require.NoError(json.Unmarshal(response, &r))
			tc.assertions(assert, r.Response)
		})
	}
}
