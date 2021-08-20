package injector

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/edgelesssys/marblerun/util"
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
)

// Mutator struct
type Mutator struct {
	// CoordAddr contains the address of the marblerun coordinator
	CoordAddr   string
	DomainName  string
	SGXResource string
}

// HandleMutate handles mutate requests and injects sgx tolerations into the request
func (m *Mutator) HandleMutate(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling mutate request, injecting sgx tolerations")
	body := checkRequest(w, r)
	if body == nil {
		// Error was already written to w
		return
	}

	// mutate the request and add sgx tolerations to pod
	mutatedBody, err := mutate(body, m.CoordAddr, m.DomainName, m.SGXResource, true)
	if err != nil {
		http.Error(w, "unable to mutate request", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(mutatedBody)
}

// HandleMutateNoSgx is called when the sgx injection label is not set
func (m *Mutator) HandleMutateNoSgx(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling mutate request, omitting sgx injection")
	body := checkRequest(w, r)
	if body == nil {
		// Error was already written to w
		return
	}

	// mutate the request and add sgx tolerations to pod
	mutatedBody, err := mutate(body, m.CoordAddr, m.DomainName, m.SGXResource, false)
	if err != nil {
		http.Error(w, "unable to mutate request", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(mutatedBody)
}

// mutate handles the creation of json patches for pods
func mutate(body []byte, coordAddr string, domainName string, resourceKey string, injectSgx bool) ([]byte, error) {
	admReviewReq := v1.AdmissionReview{}
	if err := json.Unmarshal(body, &admReviewReq); err != nil {
		log.Println("Unable to mutate request: invalid admission review")
		return nil, errors.New("invalid admission review")
	}

	if admReviewReq.Request == nil {
		log.Println("Unable to mutate request: empty admission review request")
		return nil, errors.New("empty admission request")
	}

	var pod corev1.Pod
	if err := json.Unmarshal(admReviewReq.Request.Object.Raw, &pod); err != nil {
		log.Println("Unable to mutate request: invalid pod")
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

	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}

	// get marble type from pod labels
	marbleType := pod.Labels[util.MarbleTypeLabel]
	// allow pod to start if label does not exist, but dont inject any values
	if len(marbleType) == 0 {
		resp := admission.PatchResponseFromRaw(admReviewReq.Request.Object.Raw, nil)
		admReviewResponse.Response = &resp.AdmissionResponse
		admReviewResponse.Response.Allowed = true
		admReviewResponse.Response.Result = &metav1.Status{
			Status:  "Success",
			Message: fmt.Sprintf("Missing [%s] label, injection skipped", util.MarbleTypeLabel),
		}
		bytes, err := json.Marshal(admReviewResponse)
		if err != nil {
			log.Println("Error: unable to marshal admission response")
			return nil, errors.New("unable to marshal admission response")
		}
		log.Printf("Pod is missing [%s] label, skipping injection", util.MarbleTypeLabel)
		return bytes, nil
	}

	// get namespace of pod
	namespace := pod.Namespace
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
			Value: fmt.Sprintf("%s,%s.%s,%s.%s.svc.%s", marbleType, marbleType, namespace, marbleType, namespace, domainName),
		},
	}

	var needUUIDVolume bool

	for idx, container := range pod.Spec.Containers {
		// check if we need to supply a UUID
		if !envIsSet(container.Env, corev1.EnvVar{Name: envMarbleUUIDFile}) {
			needUUIDVolume = true

			newEnvVars = append(newEnvVars, corev1.EnvVar{
				Name:  envMarbleUUIDFile,
				Value: fmt.Sprintf("/%s-uid/uuid-file", marbleType),
			})

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
			case util.IntelEpc.String():
				setResourceLimit(container.Resources.Limits, util.IntelEpc, util.GetEPCResourceLimit(resourceKey))
				setResourceLimit(container.Resources.Limits, util.IntelEnclave, "1")
				setResourceLimit(container.Resources.Limits, util.IntelProvision, "1")
			case util.AzureEpc.String():
				setResourceLimit(container.Resources.Limits, util.AzureEpc, "10")
			case util.AlibabaEpc.String():
				setResourceLimit(container.Resources.Limits, util.AlibabaEpc, "10")
			default:
				log.Println("Error: Tried to inject unkown resource key")
			}
		}

		pod.Spec.Containers[idx] = container
	}

	// if we created a volume mount for the Marble's UUID we create the volume here
	if needUUIDVolume {
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: fmt.Sprintf("uuid-file-%s", admReviewReq.Request.UID),
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

	// create the patch
	marshaledPod, err := json.Marshal(pod)
	if err != nil {
		log.Println("Error: unable to marshal patched pod")
		return nil, errors.New("unable to marshal patched pod")
	}
	resp := admission.PatchResponseFromRaw(admReviewReq.Request.Object.Raw, marshaledPod)
	if err := resp.Complete(admission.Request{AdmissionRequest: *admReviewReq.Request}); err != nil {
		log.Println("Error: patching failed")
		return nil, errors.New("patching failed")
	}

	admReviewResponse.Response = &resp.AdmissionResponse
	admReviewResponse.Response.Allowed = true
	bytes, err := json.Marshal(admReviewResponse)
	if err != nil {
		log.Println("Error: unable to marshal admission response")
		return nil, errors.New("unable to marshal admission response")
	}

	log.Printf("Mutation request for pod of marble type [%s] successful", marbleType)
	return bytes, nil
}

// checkRequest verifies the request used was POST and not empty
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

// setResourceLimit sets an SGX resource limit if it has not already been set
func setResourceLimit(target map[corev1.ResourceName]resource.Quantity, key corev1.ResourceName, value string) {
	if _, ok := target[key]; !ok {
		target[key] = resource.MustParse(value)
	}
}
