// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package injector

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/edgelesssys/marblerun/util/k8sutil"
	v1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	envMarbleCoordinatorAddr = "EDG_MARBLE_COORDINATOR_ADDR"
	envMarbleType            = "EDG_MARBLE_TYPE"
	envMarbleDNSName         = "EDG_MARBLE_DNS_NAMES"
	envMarbleUUIDFile        = "EDG_MARBLE_UUID_FILE"
	labelMarbleType          = "marblerun/marbletype"
	labelMarbleContainer     = "marblerun/marblecontainer"
	labelResourceInjection   = "marblerun/resource-injection"
)

// Mutator struct.
type Mutator struct {
	// CoordAddr contains the address of the MarbleRun coordinator
	CoordAddr   string
	DomainName  string
	SGXResource string
}

// HandleMutate handles mutate requests and injects sgx tolerations into the request.
func (m *Mutator) HandleMutate(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling mutate request, injecting sgx tolerations")
	body := checkRequest(w, r)
	if body == nil {
		// Error was already written to w
		return
	}

	// mutate the request and add sgx tolerations to pod
	mutatedBody, err := mutate(body, m.CoordAddr, m.DomainName, m.SGXResource)
	if err != nil {
		http.Error(w, fmt.Sprintf("unable to mutate request: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(mutatedBody)
}

// mutate handles the creation of json patches for pods.
func mutate(body []byte, coordAddr, domainName, resourceKey string) ([]byte, error) {
	admReviewReq := v1.AdmissionReview{}
	if err := json.Unmarshal(body, &admReviewReq); err != nil {
		log.Println("Unable to mutate request: invalid admission review")
		return nil, fmt.Errorf("invalid admission review: %v", err)
	}

	if admReviewReq.Request == nil {
		log.Println("Unable to mutate request: empty admission review request")
		return nil, errors.New("empty admission request")
	}

	var pod corev1.Pod
	if err := json.Unmarshal(admReviewReq.Request.Object.Raw, &pod); err != nil {
		log.Println("Unable to mutate request: invalid pod")
		return nil, fmt.Errorf("invalid pod: %v", err)
	}

	// admission response
	admReviewResponse := v1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AdmissionReview",
			APIVersion: "admission.k8s.io/v1",
		},
		Response: &v1.AdmissionResponse{
			UID: admReviewReq.Request.UID,
		},
	}

	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}

	// get marble type from pod labels
	marbleType, exists := pod.Labels[labelMarbleType]
	if !exists {
		// admission request was sent for a pod without marblerun/marbletype label, this should not happen
		return generateResponse(pod, admReviewReq, admReviewResponse, false, fmt.Sprintf("Error: missing [%s] label, request denied", labelMarbleType))
	}
	if len(marbleType) <= 0 {
		// deny request if the label exists, but is empty
		return generateResponse(pod, admReviewReq, admReviewResponse, false, fmt.Sprintf("Error: empty [%s] label, request denied", labelMarbleType))
	}

	injectSgx := false
	if pod.Labels[labelResourceInjection] != "disabled" {
		injectSgx = true
	}

	// get namespace of pod
	namespace := admReviewReq.Request.Namespace
	if len(namespace) == 0 {
		namespace = "default"
	}

	newEnvVars := []corev1.EnvVar{
		{
			Name:  envMarbleCoordinatorAddr,
			Value: coordAddr,
		},
		{
			Name:  envMarbleType,
			Value: marbleType,
		},
		{
			Name:  envMarbleDNSName,
			Value: strings.ToLower(fmt.Sprintf("%s,%s.%s,%s.%s.svc.%s", marbleType, marbleType, namespace, marbleType, namespace, domainName)),
		},
	}

	needUUIDVolume := false
	injectAllContainers := false

	marbleContainer := pod.Labels[labelMarbleContainer]
	if marbleContainer == "" {
		injectAllContainers = true
	}

	for idx, container := range pod.Spec.Containers {
		// skip container if the marblerun/marblecontainer label was set and the container names dont match
		if (container.Name != marbleContainer) && !injectAllContainers {
			continue
		}

		// check if we need to supply a UUID
		if !envIsSet(container.Env, corev1.EnvVar{Name: envMarbleUUIDFile}) {
			needUUIDVolume = true
			newEnvVars = append(newEnvVars, corev1.EnvVar{
				Name:  envMarbleUUIDFile,
				Value: fmt.Sprintf("/%s-uid/uuid-file", marbleType),
			})
		}

		// Verify no volume mount exists for the UUID file
		for _, volumeMount := range container.VolumeMounts {
			if volumeMount.MountPath == fmt.Sprintf("/%s-uid", marbleType) {
				needUUIDVolume = false
				break
			}
		}

		if needUUIDVolume {
			// If we need to set the uuid env variable we also need to create a volume mount, which the variable points to
			container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
				MountPath: fmt.Sprintf("/%s-uid", marbleType),
				Name:      fmt.Sprintf("uuid-file-%s", admReviewReq.Request.UID),
			})
		}

		// inject MarbleRun required env variables if they are not already set
		for _, newVar := range newEnvVars {
			if !envIsSet(container.Env, newVar) {
				container.Env = append(container.Env, newVar)
			}
		}

		// inject SGX resource limits depending on the used device plugin
		if injectSgx {
			if container.Resources.Limits == nil {
				container.Resources.Limits = make(map[corev1.ResourceName]resource.Quantity)
			}
			switch resourceKey {
			case k8sutil.IntelEpc.String():
				// Intels device plugin offers 3 resources:
				//  epc			: sets EPC for the container
				//  enclave		: provides a handle to /dev/sgx_enclave
				//  provision	: provides a handle to /dev/sgx_provision, this is not needed when the Marble utilises out-of-process quote-generation
				setResourceLimit(container.Resources.Limits, k8sutil.IntelEpc, k8sutil.GetEPCResourceLimit(resourceKey))
				setResourceLimit(container.Resources.Limits, k8sutil.IntelEnclave, "1")
				setResourceLimit(container.Resources.Limits, k8sutil.IntelProvision, "1")
			default:
				// Azure and Alibaba Cloud plugins offer only 1 resource
				// for custom plugins we can only inject the resource provided by the `resourceKey`
				setResourceLimit(container.Resources.Limits, corev1.ResourceName(resourceKey), k8sutil.GetEPCResourceLimit(resourceKey))
			}
		}

		pod.Spec.Containers[idx] = container
	}

	// if we created a volume mount for the Marble's UUID we create the volume here
	if needUUIDVolume {
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: fmt.Sprintf("uuid-file-%s", admReviewReq.Request.UID),
			VolumeSource: corev1.VolumeSource{
				// UUID of the Marble is the UUID of the Pod
				DownwardAPI: &corev1.DownwardAPIVolumeSource{
					Items: []corev1.DownwardAPIVolumeFile{
						{
							Path: "uuid-file",
							FieldRef: &corev1.ObjectFieldSelector{
								FieldPath: "metadata.uid",
							},
						},
					},
				},
			},
		})
	}

	// inject sgx tolerations if enabled
	if injectSgx {
		pod.Spec.Tolerations = append(pod.Spec.Tolerations, corev1.Toleration{
			Key:      resourceKey,
			Operator: corev1.TolerationOpExists,
			Effect:   corev1.TaintEffectNoSchedule,
		})
	}

	return generateResponse(pod, admReviewReq, admReviewResponse, true, fmt.Sprintf("Mutation request for pod of marble type [%s] successful", marbleType))
}

// checkRequest verifies the request used was POST and not empty.
func checkRequest(w http.ResponseWriter, r *http.Request) []byte {
	if r.Method != http.MethodPost {
		http.Error(w, "unable to handle requests other than POST", http.StatusBadRequest)
		return nil
	}

	if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
		http.Error(w, "wrong application type", http.StatusBadRequest)
		return nil
	}

	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		http.Error(w, fmt.Sprintf("unable to read request: %v", err), http.StatusBadRequest)
		return nil
	}

	return body
}

// envIsSet checks if an env variable is already set.
func envIsSet(setVars []corev1.EnvVar, testVar corev1.EnvVar) bool {
	if len(setVars) == 0 {
		return false
	}
	for _, setVar := range setVars {
		if setVar.Name == testVar.Name {
			return true
		}
	}
	return false
}

// setResourceLimit sets an SGX resource limit if it has not already been set.
func setResourceLimit(target map[corev1.ResourceName]resource.Quantity, key corev1.ResourceName, value string) {
	if _, ok := target[key]; !ok {
		target[key] = resource.MustParse(value)
	}
}

// generateResponse creates the admission response.
func generateResponse(pod corev1.Pod, request, response v1.AdmissionReview, allowed bool, message string) ([]byte, error) {
	marshaledPod, err := json.Marshal(pod)
	if err != nil {
		log.Println("Error: unable to marshal patched pod")
		return nil, fmt.Errorf("unable to marshal patched pod: %v", err)
	}
	resp := admission.PatchResponseFromRaw(request.Request.Object.Raw, marshaledPod)
	if err := resp.Complete(admission.Request{AdmissionRequest: *request.Request}); err != nil {
		log.Println("Error: patching failed")
		return nil, fmt.Errorf("patching failed: %v", err)
	}

	response.Response = &resp.AdmissionResponse
	response.Response.Allowed = allowed
	var status string
	if allowed {
		status = "Success"
	} else {
		status = "Failure"
	}
	response.Response.Result = &metav1.Status{
		Status:  status,
		Message: message,
	}

	bytes, err := json.Marshal(response)
	if err != nil {
		log.Println("Error: unable to marshal admission response")
		return nil, fmt.Errorf("unable to marshal admission response: %v", err)
	}

	log.Println(message)

	return bytes, nil
}
