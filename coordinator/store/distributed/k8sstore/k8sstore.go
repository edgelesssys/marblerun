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

	"github.com/edgelesssys/marblerun/coordinator/store/distributed/transaction"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Client handles interaction with the Kubernetes API to store and retrieve the state.
type Client struct {
	client     kubectl
	namespace  string
	secretName string
	log        *zap.Logger
}

// New creates a new k8sstore Client.
func New(client kubernetes.Interface, namespace, secretName string, log *zap.Logger) *Client {
	return &Client{
		client:     &kubeClient{client: client},
		namespace:  namespace,
		secretName: secretName,
		log:        log,
	}
}

// GetState retrieves the state from Kubernetes.
func (c *Client) GetState(ctx context.Context) (*transaction.State, error) {
	c.log.Debug("Retrieving state from Kubernetes Secret", zap.String("namespace", c.namespace), zap.String("name", c.secretName))
	state, err := c.client.getSecret(ctx, c.namespace, c.secretName)
	if err == nil {
		c.log.Debug("State retrieved successfully, creating state transaction")
		return &transaction.State{
			SealedData: state.Data[stdstore.SealedDataFname],
			SealedKey:  state.Data[stdstore.SealedKeyFname],
			StateRef:   state,
		}, nil
	}

	// Try to create the state if it doesn't exist yet
	if k8serrors.IsNotFound(err) {
		c.log.Debug("State not found, creating new state")
		ref, err := c.createState(ctx)
		return &transaction.State{StateRef: ref}, err
	}

	return nil, fmt.Errorf("loading state from Kubernetes: %w", err)
}

// SaveState saves the state to Kubernetes.
func (c *Client) SaveState(ctx context.Context, state *transaction.State) error {
	c.log.Debug("Saving state to Kubernetes Secret", zap.String("namespace", c.namespace), zap.String("name", c.secretName))
	ref, ok := state.StateRef.(*corev1.Secret)
	if !ok {
		return errors.New("invalid state reference: expected *corev1.Secret")
	}

	if ref.Data == nil {
		c.log.Debug("State data is nil, initializing data map")
		ref.Data = map[string][]byte{}
	}

	ref.Data[stdstore.SealedDataFname] = state.SealedData
	ref.Data[stdstore.SealedKeyFname] = state.SealedKey

	c.log.Debug("Updating state Secret in Kubernetes", zap.String("namespace", c.namespace), zap.String("name", c.secretName))
	if err := c.client.updateSecret(ctx, c.namespace, ref); err != nil {
		if k8serrors.IsConflict(err) {
			return errors.New("a newer version of the state exists in Kubernetes: apply changes and retry operation")
		}
		return fmt.Errorf("updating state in Kubernetes: %w", err)
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

type kubectl interface {
	createSecret(ctx context.Context, namespace string, secret *corev1.Secret) (*corev1.Secret, error)
	getSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error)
	updateSecret(ctx context.Context, namespace string, secret *corev1.Secret) error
}
