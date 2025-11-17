//go:build fakestore

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package k8sstore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NewWithFakeK8s creates a new k8sstore Client with a fake kube client backed by files in sealDir.
func NewWithFakeK8s(namespace, secretName, sealDir string, log *zap.Logger) *Client {
	return &Client{
		client:     &fakeKubeClient{sealDir: sealDir},
		namespace:  namespace,
		secretName: secretName,
		log:        log,
	}
}

type fakeKubeClient struct {
	sealDir string
}

func (c *fakeKubeClient) createSecret(_ context.Context, _ string, _ *corev1.Secret) (*corev1.Secret, error) {
	panic("not implemented")
}

func (c *fakeKubeClient) getSecret(_ context.Context, namespace, name string) (*corev1.Secret, error) {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name}}
	data, err := os.ReadFile(c.makePath(namespace, name))
	if errors.Is(err, os.ErrNotExist) {
		return secret, nil
	} else if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, secret); err != nil {
		return nil, err
	}
	return secret, nil
}

func (c *fakeKubeClient) updateSecret(_ context.Context, namespace string, secret *corev1.Secret) error {
	data, err := json.Marshal(secret)
	if err != nil {
		return err
	}
	return os.WriteFile(c.makePath(namespace, secret.Name), data, 0o644)
}

func (c *fakeKubeClient) makePath(namespace, name string) string {
	return filepath.Join(c.sealDir, namespace+"-"+name)
}
