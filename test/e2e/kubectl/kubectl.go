/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package kubectl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

const waitInterval = time.Second

// Kubectl is a wrapper for the Kubernetes client.
type Kubectl struct {
	t *testing.T

	client *kubernetes.Clientset
	config *rest.Config
}

// New initializes a new Kubectl instance.
func New(t *testing.T, kubeConfigPath string) (*Kubectl, error) {
	t.Helper()

	kubeConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("getting kubernetes config file: %w", err)
	}

	kubectl, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("setting up kubectl: %w", err)
	}
	return &Kubectl{
		t:      t,
		client: kubectl,
		config: kubeConfig,
	}, nil
}

// SetUpNamespace creates a namespace and a pull secret for the MarbleRun installation.
func (k *Kubectl) SetUpNamespace(ctx context.Context, namespace, accessToken string) (string, func(), error) {
	k.t.Helper()

	uid := generateUID()
	namespace += "-" + uid

	label := "marblerun/e2e-test"
	if _, err := k.client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
			Labels: map[string]string{
				label: uid,
			},
		},
	}, metav1.CreateOptions{}); err != nil {
		return "", nil, fmt.Errorf("creating namespace: %w", err)
	}

	cleanUp := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute) // 10 Minute wait for deletion
		defer cancel()

		deleteNs := func() error {
			if err := k.client.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{}); err != nil {
				k.t.Logf("Deleting namespace: %s", err)
				return err
			}
			return nil
		}

		watcher, err := k.client.CoreV1().Namespaces().Watch(ctx, metav1.ListOptions{
			LabelSelector: fmt.Sprintf("%s=%s", label, uid),
		})
		if err != nil {
			k.t.Logf("Watching namespace: %s\n", err)
			_ = deleteNs()
			return
		}

		if err := deleteNs(); err != nil {
			return
		}

		defer watcher.Stop()
		for {
			select {
			case event := <-watcher.ResultChan():
				if event.Type == watch.Deleted {
					return
				}
			case <-ctx.Done():
				k.t.Logf("Waiting for namespace to be deleted: %s", ctx.Err())
				return
			}
		}
	}

	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", accessToken, accessToken)))
	if _, err := k.client.CoreV1().Secrets(namespace).Create(
		ctx,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "access-token",
				Namespace: namespace,
			},
			Data: map[string][]byte{
				".dockerconfigjson": []byte(fmt.Sprintf(`{"auths":{"ghcr.io":{"auth":"%s"}}}`, auth)),
			},
			Type: corev1.SecretTypeDockerConfigJson,
		},
		metav1.CreateOptions{},
	); err != nil {
		cleanUp()
		return "", nil, fmt.Errorf("creating pullSecret: %w", err)
	}

	return uid, cleanUp, nil
}

// GetAvailablePodNamesForService returns a list of all available Pods for a service.
func (k *Kubectl) GetAvailablePodNamesForService(ctx context.Context, namespace, serviceName string) ([]string, error) {
	k.t.Helper()

	service, err := k.client.CoreV1().Services(namespace).Get(ctx, serviceName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting service: %w", err)
	}

	return k.getAvailablePodNames(ctx, namespace, labels.Set(service.Spec.Selector).String())
}

// GetAvailablePodNamesForDeployment returns a list of all available Pods for a deployment.
func (k *Kubectl) GetAvailablePodNamesForDeployment(ctx context.Context, namespace, deploymentName string) ([]string, error) {
	k.t.Helper()

	deployment, err := k.client.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting deployment: %w", err)
	}

	return k.getAvailablePodNames(ctx, namespace, labels.Set(deployment.Spec.Selector.MatchLabels).String())
}

// PortForwardPod starts a port forward to the selected pod.
// The function will wait until the connection to the forwarded port can be established.
func (k *Kubectl) PortForwardPod(ctx context.Context, namespace, podName, remotePort string) (string, func(), error) {
	k.t.Helper()

	// Stop and ready channels for the port forward
	stopCh := make(chan struct{}, 1)
	readyCh := make(chan struct{})
	var closeOnce sync.Once
	stop := func() { closeOnce.Do(func() { close(stopCh) }) }

	// REST request to start port forwarding
	req := k.client.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(namespace).
		Name(podName).
		SubResource("portforward")

	// Create a round tripper for the port forward
	transport, upgrader, err := spdy.RoundTripperFor(k.config)
	if err != nil {
		return "", nil, fmt.Errorf("creating round tripper: %w", err)
	}

	// Custom dialer using the forward request
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, req.URL())

	logWriter := &logWriter{t: k.t}
	// Initialize and start forwarding
	fw, err := portforward.NewOnAddresses(
		dialer,
		[]string{"localhost"},
		[]string{fmt.Sprintf("0:%s", remotePort)},
		stopCh, readyCh,
		logWriter, logWriter,
	)
	if err != nil {
		return "", nil, fmt.Errorf("creating portforwarder: %w", err)
	}

	go func() {
		if err := fw.ForwardPorts(); err != nil {
			stop()
			k.t.Logf("Error forwarding port for pod %q in namespace %q: %s", podName, namespace, err)

			// Get all Pods currently running in the namespace to print as debug message
			pods, err := k.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				k.t.Logf("Error listing pods: %s", err)
				return
			}
			msg := fmt.Sprintf("Currently running pods in namespace %q:", namespace)
			for _, pod := range pods.Items {
				var conditions []string
				for _, condition := range pod.Status.Conditions {
					conditions = append(conditions, fmt.Sprintf("%+v", condition))
				}
				msg += fmt.Sprintf(
					"\n Name: %s, Phase: %s, Conditions: %v",
					pod.Name, pod.Status.Phase, conditions,
				)
			}
			k.t.Log(msg)
		}
	}()

	select {
	case <-stopCh:
		return "", nil, errors.New("port forwarding failed")

	case <-readyCh:
		ports, err := fw.GetPorts()
		if err != nil {
			stop()
			return "", nil, fmt.Errorf("getting ports: %w", err)
		}
		port := strconv.Itoa(int(ports[0].Local))
		cleanUp := func() {
			k.t.Logf("Stopping port forward from localhost:%s to %s:%s in namespace %q", port, podName, remotePort, namespace)
			stop()
		}

		waitCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		if err := waitForConnectionReady(waitCtx, k.t, "localhost", port); err != nil {
			cleanUp()
			return "", nil, fmt.Errorf("waiting for connection to be ready: %w", err)
		}
		k.t.Logf("Forwarding from localhost:%s to %s:%s in namespace %q", port, podName, remotePort, namespace)
		return port, cleanUp, nil

	case <-ctx.Done():
		stop()
		return "", nil, fmt.Errorf("waiting for port forward to be ready: %w", ctx.Err())
	}
}

// ScaleDeployment scales a deployment to the given number of replicas,
// and waits until the deployment has the desired number of replicas.
func (k *Kubectl) ScaleDeployment(ctx context.Context, namespace, deploymentName string, replicas int) error {
	k.t.Helper()

	// Get label selector from deployment
	deployment, err := k.client.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("getting deployment: %w", err)
	}
	labelSelector := labels.Set(deployment.Spec.Selector.MatchLabels).String()

	scale, err := k.client.AppsV1().Deployments(namespace).GetScale(ctx, deploymentName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("getting deployment scale: %w", err)
	}

	scale.Spec.Replicas = int32(replicas)
	if _, err := k.client.AppsV1().Deployments(namespace).UpdateScale(ctx, deploymentName, scale, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("updating deployment scale: %w", err)
	}

	return k.waitForPods(ctx, namespace, labelSelector, replicas, podReady)
}

// GetDeploymentImage returns the image name of a container in a deployment.
func (k *Kubectl) GetDeploymentImage(ctx context.Context, namespace, deploymentName, containerName string) (string, error) {
	k.t.Helper()

	deployment, err := k.client.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("getting deployment: %w", err)
	}

	containers := deployment.Spec.Template.Spec.Containers
	for _, c := range containers {
		if c.Name == containerName {
			return c.Image, nil
		}
	}

	return "", errors.New("container not found")
}

// SetDeploymentImage sets the image name of a container in a deployment
// and waits until the image is rolled out.
func (k *Kubectl) SetDeploymentImage(ctx context.Context, namespace, deploymentName, containerName, imageName string) error {
	k.t.Helper()

	deployment, err := k.client.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("getting deployment: %w", err)
	}

	// Update image name for specified container
	containerIdx := -1
	containers := deployment.Spec.Template.Spec.Containers
	for i, c := range containers {
		if c.Name == containerName {
			containerIdx = i
			break
		}
	}
	if containerIdx == -1 {
		return errors.New("container not found")
	}

	stringPatch := patchStringValue{
		Op:    "replace",
		Path:  fmt.Sprintf("/spec/template/spec/containers/%d/image", containerIdx),
		Value: imageName,
	}
	patch, err := json.Marshal([]any{stringPatch})
	if err != nil {
		return fmt.Errorf("marshaling patch: %w", err)
	}

	_, err = k.client.AppsV1().Deployments(namespace).Patch(ctx, deploymentName, types.JSONPatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("patching deployment: %w", err)
	}

	// Wait until all pods have the new image
	labelSelector := labels.Set(deployment.Spec.Selector.MatchLabels).String()
	return k.waitForPods(ctx, namespace, labelSelector, int(*deployment.Spec.Replicas),
		func(pod corev1.Pod) bool {
			for _, c := range pod.Spec.Containers {
				if c.Image == imageName {
					return podReady(pod)
				}
			}
			return false
		},
	)
}

// AssignDeploymentToNode assigns a deployment to a node.
func (k *Kubectl) AssignDeploymentToNode(ctx context.Context, namespace, deploymentName, nodeName string) error {
	k.t.Helper()

	deployment, err := k.client.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("getting deployment: %w", err)
	}

	stringPatch := patchStringValue{
		Op:    "add",
		Path:  "/spec/template/spec/nodeName",
		Value: nodeName,
	}
	patch, err := json.Marshal([]any{stringPatch})
	if err != nil {
		return fmt.Errorf("marshaling patch: %w", err)
	}

	_, err = k.client.AppsV1().Deployments(namespace).Patch(ctx, deploymentName, types.JSONPatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("patching deployment: %w", err)
	}

	// Wait until all pods are assigned to the node
	labelSelector := labels.Set(deployment.Spec.Selector.MatchLabels).String()
	return k.waitForPods(ctx, namespace, labelSelector, int(*deployment.Spec.Replicas),
		func(pod corev1.Pod) bool {
			return pod.Spec.NodeName == nodeName && podReady(pod)
		},
	)
}

// CloneDeployment clones a deployment. The new deployment will be scaled to 0.
// labelName is the name of the label that will get another value for the new deployment.
func (k *Kubectl) CloneDeployment(ctx context.Context, namespace, existingDeploymentName, newDeploymentName, labelName string) error {
	k.t.Helper()

	deployment, err := k.client.AppsV1().Deployments(namespace).Get(ctx, existingDeploymentName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("getting deployment: %w", err)
	}

	deployment.Name = newDeploymentName
	deployment.ResourceVersion = "" // needs to be empty for create
	deployment.Spec.Replicas = new(int32)

	// Set new label so that pods of the new deployment aren't selected by the old one and vice versa
	deployment.Spec.Template.Labels[labelName] = newDeploymentName
	deployment.Spec.Selector.MatchLabels[labelName] = newDeploymentName

	_, err = k.client.AppsV1().Deployments(namespace).Create(ctx, deployment, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("creating deployment: %w", err)
	}

	return nil
}

// DeleteConfigMap deletes a ConfigMap.
func (k *Kubectl) DeleteConfigMap(ctx context.Context, namespace, cfgName string) error {
	k.t.Helper()

	k.t.Logf("Deleting ConfigMap %s in namespace %s", cfgName, namespace)
	if err := k.client.CoreV1().ConfigMaps(namespace).Delete(ctx, cfgName, metav1.DeleteOptions{}); err != nil {
		if k8serrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("deleting ConfigMap: %w", err)
	}

	ticker := time.NewTicker(waitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for ConfigMap to be deleted: %w", ctx.Err())
		case <-ticker.C:
			if _, err := k.client.CoreV1().ConfigMaps(namespace).Get(ctx, cfgName, metav1.GetOptions{}); err != nil {
				if k8serrors.IsNotFound(err) {
					return nil
				}
				k.t.Logf("Error getting ConfigMap: %s", err)
			}
		}
	}
}

// CreateSecret creates a secret.
func (k *Kubectl) CreateSecret(ctx context.Context, namespace, secretName string, data map[string][]byte) error {
	k.t.Helper()

	secret := &corev1.Secret{Data: data}
	secret.Name = secretName
	_, err := k.client.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	return err
}

// UpdateSecret updates a secret.
func (k *Kubectl) UpdateSecret(ctx context.Context, namespace, secretName string, data map[string][]byte) error {
	k.t.Helper()

	secret := &corev1.Secret{Data: data}
	secret.Name = secretName
	_, err := k.client.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
	return err
}

// GetSecretData returns a secret's data.
func (k *Kubectl) GetSecretData(ctx context.Context, namespace, secretName string) (map[string][]byte, error) {
	k.t.Helper()

	secret, err := k.client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return secret.Data, nil
}

// CreatePod creates a pod using the given spec.
// Returns the name of the created pod.
func (k *Kubectl) CreatePod(ctx context.Context, pod *corev1.Pod) (string, error) {
	k.t.Helper()
	pod.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "access-token"}}
	pod, err := k.client.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	return pod.Name, err
}

// GetPod returns a pod.
func (k *Kubectl) GetPod(ctx context.Context, namespace, podName string) (*corev1.Pod, error) {
	k.t.Helper()

	return k.client.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
}

// DeletePod deletes a pod.
func (k *Kubectl) DeletePod(ctx context.Context, namespace, podName string) error {
	k.t.Logf("Deleting Pod %s in namespace %s", podName, namespace)
	if err := k.client.CoreV1().Pods(namespace).Delete(ctx, podName, metav1.DeleteOptions{}); err != nil {
		if k8serrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("deleting Pod: %w", err)
	}

	ticker := time.NewTicker(waitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for Pod to be deleted: %w", ctx.Err())
		case <-ticker.C:
			if _, err := k.client.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{}); err != nil {
				if k8serrors.IsNotFound(err) {
					return nil
				}
				k.t.Logf("Error getting Pod: %s", err)
			}
		}
	}
}

// GetSGXNodes returns a list of all nodes that have SGX support.
func (k *Kubectl) GetSGXNodes(ctx context.Context) ([]string, error) {
	k.t.Helper()

	nodes, err := k.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing nodes: %w", err)
	}

	var nodeNames []string
	for _, n := range nodes.Items {
		if !n.Status.Allocatable.Name("sgx.intel.com/enclave", "").IsZero() {
			nodeNames = append(nodeNames, n.Name)
		}
	}

	return nodeNames, nil
}

// GetLogsFromNamespace returns the logs of all pods in a namespace.
func (k *Kubectl) GetLogsFromNamespace(ctx context.Context, namespace string) (map[string][]byte, error) {
	k.t.Helper()

	pods, err := k.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}

	logs := make(map[string][]byte, len(pods.Items))
	for _, p := range pods.Items {
		podLogs, err := k.client.CoreV1().Pods(namespace).GetLogs(p.Name, &corev1.PodLogOptions{}).Do(ctx).Raw()
		if err != nil {
			return nil, fmt.Errorf("getting logs: %w", err)
		}
		logs[p.Name] = podLogs
	}

	return logs, nil
}

func (k *Kubectl) getAvailablePodNames(ctx context.Context, namespace string, labelSelector string) ([]string, error) {
	k.t.Helper()

	pod, err := k.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}
	if len(pod.Items) == 0 {
		return nil, errors.New("no pod found")
	}

	var podNames []string
	for _, p := range pod.Items {
		podNames = append(podNames, p.Name)
	}

	return podNames, nil
}

func (k *Kubectl) waitForPods(ctx context.Context, namespace string, labelSelector string, replicas int, condition func(corev1.Pod) bool) error {
	k.t.Helper()

	ticker := time.NewTicker(waitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for deployment to have %d replicas: %w", replicas, ctx.Err())
		case <-ticker.C:
			podList, err := k.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
				LabelSelector: labelSelector,
			})
			if err != nil {
				k.t.Logf("Error listing coordinator pods: %s", err)
				continue
			}
			podNames := make([]string, len(podList.Items))
			for i, pod := range podList.Items {
				podNames[i] = pod.Name
			}
			if len(podList.Items) != replicas {
				k.t.Logf("Waiting for deployment to have %d available replicas, currently %d: %v", replicas, len(podList.Items), podNames)
				continue
			}

			podsSatisfyCondition := true
			for _, pod := range podList.Items {
				if !condition(pod) {
					podsSatisfyCondition = false
					break
				}
			}

			if podsSatisfyCondition {
				k.t.Log("Deployment has the desired number of replicas and all pods satisfy the condition")
				return nil
			}
		}
	}
}

func podReady(pod corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

// waitForConnectionReady waits for a connection to be ready.
func waitForConnectionReady(ctx context.Context, t *testing.T, host, port string) error {
	t.Helper()

	ticker := time.NewTicker(waitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for connection to be ready: %w", ctx.Err())
		case <-ticker.C:
			if conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, port)); err == nil {
				_ = conn.Close()
				return nil
			}
		}
	}
}

func generateUID() string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	b := make([]rune, 6)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

type logWriter struct {
	t *testing.T
}

func (l *logWriter) Write(p []byte) (n int, err error) {
	l.t.Logf("%s", string(p))
	return len(p), nil
}

type patchStringValue struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value string `json:"value"`
}
