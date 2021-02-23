package mutate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	v1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CoordAddr contains the address of the marblerun coordinator
var CoordAddr string

// HandleMutate handles mutate requests and injects sgx tolerations into the request
func HandleMutate(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling mutate request, injecting sgx tolerations")
	body := checkRequest(w, r)
	if body == nil {
		// Error was already written to w
		return
	}

	// mutate the request and add sgx tolerations to pod
	mutatedBody, err := mutate(body, true)
	if err != nil {
		http.Error(w, "unable to mutate request", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(mutatedBody)
}

// HandleMutateNoSgx is called when the sgx injection label is not set
func HandleMutateNoSgx(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling mutate request, omitting sgx injection")
	body := checkRequest(w, r)
	if body == nil {
		// Error was already written to w
		return
	}

	// mutate the request and add sgx tolerations to pod
	mutatedBody, err := mutate(body, false)
	if err != nil {
		http.Error(w, "unable to mutate request", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(mutatedBody)
}

// mutate handles the creation of json patches for pods
func mutate(body []byte, injectSgx bool) ([]byte, error) {
	admReviewReq := v1.AdmissionReview{}
	if err := json.Unmarshal(body, &admReviewReq); err != nil {
		return nil, errors.New("invalid admission review")
	}

	if admReviewReq.Request == nil {
		return nil, errors.New("empty admission request")
	}

	var pod corev1.Pod
	if err := json.Unmarshal(admReviewReq.Request.Object.Raw, &pod); err != nil {
		return nil, errors.New("invalid pod")
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

	pT := v1.PatchTypeJSONPatch
	admReviewResponse.Response.PatchType = &pT

	// get marble type from pod labels
	marbleType := pod.Labels["marblerun.marbletype"]
	// reject pod if label does not exist
	if len(marbleType) == 0 {
		admReviewResponse.Response.Allowed = false
		admReviewResponse.Response.Result = &metav1.Status{
			Status: "Rejected",
			Reason: "Missing required label: [marblerun.marbletype]",
		}
		bytes, err := json.Marshal(admReviewResponse)
		if err != nil {
			return nil, errors.New("unable to marshal admission response")
		}
		return bytes, nil
	}

	// get namespace of pod
	namespace := pod.Namespace
	if len(namespace) == 0 {
		namespace = "default"
	}

	newEnvVars := []corev1.EnvVar{
		{
			Name:  "EDG_MARBLE_COORDINATOR_ADDR",
			Value: CoordAddr,
		},
		{
			Name:  "EDG_MARBLE_TYPE",
			Value: marbleType,
		},
		{
			Name:  "EDG_MARBLE_DNS_NAMES",
			Value: fmt.Sprintf("%s,%s.%s,%s.%s.svc.cluster.local", marbleType, marbleType, namespace, marbleType, namespace),
		},
		{
			Name: "EDG_MARBLE_UUID_FILE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					APIVersion: "v1",
					FieldPath:  "metadata.uid",
				},
			},
		},
	}

	var patch []map[string]interface{}

	// create env variable patches for each container of the pod
	for idx, container := range pod.Spec.Containers {
		patch = append(patch, addEnvVar(container.Env, newEnvVars, fmt.Sprintf("/spec/containers/%d/env", idx))...)
	}

	// add sgx tolerations if enabled
	if injectSgx {
		patch = append(patch, map[string]interface{}{
			"op":    "add",
			"path":  "/spec/tolerations/-",
			"value": corev1.Toleration{Key: "kubernetes.azure.com/sgx_epc_mem_in_MiB"},
		})
	}

	// convert admission response into bytes and return
	var err error
	admReviewResponse.Response.Patch, err = json.Marshal(patch)
	if err != nil {
		return nil, errors.New("unable to marshal json patch")
	}
	admReviewResponse.Response.Allowed = true
	bytes, err := json.Marshal(admReviewResponse)
	if err != nil {
		return nil, errors.New("unable to marshal admission response")
	}
	return bytes, nil
}

// check if http was POST and not empty
func checkRequest(w http.ResponseWriter, r *http.Request) []byte {
	if r.Method != http.MethodPost {
		http.Error(w, "unable to handle requests other than POST", http.StatusBadRequest)
		return nil
	}

	if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
		http.Error(w, "wrong application type", http.StatusBadRequest)
		return nil
	}

	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		http.Error(w, "unable to read request", http.StatusBadRequest)
		return nil
	}

	return body
}

// envIsSet checks if an env variable is already set
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

// addEnvVar creates a json patch setting all unset required environment variables
func addEnvVar(setVars, newVars []corev1.EnvVar, basePath string) []map[string]interface{} {
	var envPatch []map[string]interface{}
	first := len(setVars) == 0
	var newValue interface{}
	for _, newVar := range newVars {
		newValue = newVar
		path := basePath
		if first {
			first = false
			newValue = []corev1.EnvVar{newVar}
		} else {
			path = path + "/-"
		}
		if !envIsSet(setVars, newVar) {
			envPatch = append(envPatch, map[string]interface{}{
				"op":    "add",
				"path":  path,
				"value": newValue,
			})
		}
	}
	return envPatch
}
