/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// k8sstore uses Kubernetes secrets as the backing store for the Coordinator.
package k8sstore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/edgelesssys/marblerun/coordinator/store/distributed/transaction"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
)

// Client handles interaction with the Kubernetes API to store and retrieve the state.
type Client struct {
	client     kubectl
	namespace  string
	secretName string
	log        *zap.Logger
	chunking   bool
	gcMu       sync.Mutex
	nextGC     time.Time
	metrics    metrics
}

// New creates a new k8sstore Client.
func New(client kubernetes.Interface, namespace, secretName string, chunking bool, registry prometheus.Registerer, log *zap.Logger) *Client {
	return &Client{
		client:     &kubeClient{client: client},
		namespace:  namespace,
		secretName: secretName,
		log:        log,
		chunking:   chunking,
		metrics:    newMetrics(registry),
	}
}

// GetState retrieves the state from Kubernetes.
func (c *Client) GetState(ctx context.Context) (*transaction.State, error) {
	c.log.Debug("Retrieving state from Kubernetes Secret", zap.String("namespace", c.namespace), zap.String("name", c.secretName))
	state, err := c.client.getSecret(ctx, c.namespace, c.secretName)
	if err == nil {
		if _, chunked := state.Data[descriptorKey]; (chunked || c.chunking) && c.maybeCollect(ctx, state) {
			// A GC barrier changes resourceVersion. Start the transaction after it.
			state, err = c.client.getSecret(ctx, c.namespace, c.secretName)
			if err != nil {
				return nil, err
			}
		}
		return c.readState(ctx, state)
	}

	// Try to create the state if it doesn't exist yet
	if k8serrors.IsNotFound(err) {
		c.log.Debug("State not found, creating new state")
		ref, err := c.createState(ctx)
		if k8serrors.IsAlreadyExists(err) {
			return c.GetState(ctx)
		}
		return &transaction.State{StateRef: ref}, err
	}

	return nil, fmt.Errorf("loading state from Kubernetes: %w", err)
}

// SaveState saves the state to Kubernetes.
func (c *Client) SaveState(ctx context.Context, state *transaction.State) error {
	c.log.Debug("Saving state to Kubernetes Secret", zap.String("namespace", c.namespace), zap.String("name", c.secretName))
	ref, ok := state.StateRef.(*corev1.Secret)
	if !ok || ref == nil {
		return errors.New("invalid state reference: expected *corev1.Secret")
	}
	previous, revision, err := layout(ref)
	if err != nil {
		return err
	}
	if revision == ^uint64(0) {
		return errors.New("state revision overflow")
	}
	ref = ref.DeepCopy()
	if ref.Annotations == nil {
		ref.Annotations = map[string]string{}
	}
	ref.Annotations[revisionAnnotation] = strconv.FormatUint(revision+1, 10)

	if ref.Data == nil {
		c.log.Debug("State data is nil, initializing data map")
		ref.Data = map[string][]byte{}
	}

	ref.Data[stdstore.SealedDataFname] = state.SealedData
	ref.Data[stdstore.SealedKeyFname] = state.SealedKey
	if previous != nil || secretDataSize(ref) > corev1.MaxSecretSize {
		if previous == nil && !c.chunking {
			return errors.New("state exceeds the Kubernetes Secret limit: upgrade all replicas and enable coordinator.chunkedState")
		}
		if err := c.writeChunks(ctx, ref, revision+1, state.SealedData); err != nil {
			return err
		}
	}

	c.log.Debug("Updating state Secret in Kubernetes", zap.String("namespace", c.namespace), zap.String("name", c.secretName))
	if err := c.client.updateSecret(ctx, c.namespace, ref); err != nil {
		if k8serrors.IsConflict(err) {
			return errors.New("a newer version of the state exists in Kubernetes: apply changes and retry operation")
		}
		// An update may have succeeded despite a transport error. Never delete its chunks.
		if _, chunked := ref.Data[descriptorKey]; chunked {
			current, getErr := c.client.getSecret(ctx, c.namespace, c.secretName)
			if getErr == nil && current.UID == ref.UID && string(current.Data[descriptorKey]) == string(ref.Data[descriptorKey]) {
				c.observeState(revision+1, len(state.SealedData)+len(state.SealedKey))
				c.maybeCollect(ctx, current)
				return nil
			}
		}
		return fmt.Errorf("updating state in Kubernetes: %w", err)
	}
	c.observeState(revision+1, len(state.SealedData)+len(state.SealedKey))
	if _, chunked := ref.Data[descriptorKey]; chunked || c.chunking {
		c.maybeCollect(ctx, ref)
	}
	return nil
}

// createState creates the state in Kubernetes.
func (c *Client) createState(ctx context.Context) (*corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.secretName,
			Namespace: c.namespace,
		},
		Data: map[string][]byte{},
	}
	state, err := c.client.createSecret(ctx, c.namespace, secret)
	if err != nil {
		return nil, fmt.Errorf("creating state in Kubernetes: %w", err)
	}

	return state, nil
}

type kubeClient struct {
	client kubernetes.Interface
}

func (c *kubeClient) createSecret(ctx context.Context, namespace string, secret *corev1.Secret) (*corev1.Secret, error) {
	return c.client.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
}

func (c *kubeClient) getSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	return c.client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *kubeClient) updateSecret(ctx context.Context, namespace string, secret *corev1.Secret) error {
	_, err := c.client.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
	return err
}

func (c *kubeClient) listSecrets(ctx context.Context, namespace string, opts metav1.ListOptions) (*corev1.SecretList, error) {
	// GC only needs identity and age. Do not download every old ciphertext into
	// enclave memory merely to decide which objects to delete.
	var metadata metav1.PartialObjectMetadataList
	err := c.client.CoreV1().RESTClient().Get().Namespace(namespace).Resource("secrets").
		SetHeader("Accept", "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1").
		VersionedParams(&opts, scheme.ParameterCodec).Do(ctx).Into(&metadata)
	if err != nil {
		return nil, err
	}
	result := &corev1.SecretList{ListMeta: metadata.ListMeta}
	for _, item := range metadata.Items {
		result.Items = append(result.Items, corev1.Secret{ObjectMeta: item.ObjectMeta})
	}
	return result, nil
}

func (c *kubeClient) deleteSecret(ctx context.Context, namespace, name string, uid types.UID) error {
	return c.client.CoreV1().Secrets(namespace).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
}

type kubectl interface {
	createSecret(ctx context.Context, namespace string, secret *corev1.Secret) (*corev1.Secret, error)
	getSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error)
	updateSecret(ctx context.Context, namespace string, secret *corev1.Secret) error
	listSecrets(context.Context, string, metav1.ListOptions) (*corev1.SecretList, error)
	deleteSecret(context.Context, string, string, types.UID) error
}
