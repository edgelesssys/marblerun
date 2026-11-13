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
	"strconv"
	"strings"

	"github.com/gofrs/flock"
	"github.com/google/uuid"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// NewWithFakeK8s creates a new k8sstore Client with a fake kube client backed by files in sealDir.
func NewWithFakeK8s(namespace, secretName, sealDir string, log *zap.Logger) *Client {
	return &Client{
		client:     &fakeKubeClient{sealDir: sealDir},
		namespace:  namespace,
		secretName: secretName,
		log:        log,
		chunking:   true,
	}
}

type fakeKubeClient struct {
	sealDir string
}

func (c *fakeKubeClient) createSecret(ctx context.Context, namespace string, secret *corev1.Secret) (*corev1.Secret, error) {
	lock := flock.New(filepath.Join(c.sealDir, ".state-lock"))
	if err := lock.Lock(); err != nil {
		return nil, err
	}
	defer lock.Close()
	if _, err := c.getSecret(ctx, namespace, secret.Name); err == nil {
		return nil, k8serrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, secret.Name)
	} else if !k8serrors.IsNotFound(err) {
		return nil, err
	}
	secret = secret.DeepCopy()
	secret.Namespace = namespace
	secret.UID = types.UID(uuid.NewString())
	secret.ResourceVersion = "1"
	secret.CreationTimestamp = metav1.Now()
	return secret, c.write(namespace, secret)
}

func (c *fakeKubeClient) getSecret(_ context.Context, namespace, name string) (*corev1.Secret, error) {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name}}
	data, err := os.ReadFile(c.makePath(namespace, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, k8serrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, name)
	} else if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, secret); err != nil {
		return nil, err
	}
	return secret, nil
}

func (c *fakeKubeClient) updateSecret(ctx context.Context, namespace string, secret *corev1.Secret) error {
	lock := flock.New(filepath.Join(c.sealDir, ".state-lock"))
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Close()
	current, err := c.getSecret(ctx, namespace, secret.Name)
	if err != nil {
		return err
	}
	if current.ResourceVersion != secret.ResourceVersion || current.UID != secret.UID {
		return k8serrors.NewConflict(schema.GroupResource{Resource: "secrets"}, secret.Name, errors.New("stale state"))
	}
	version, err := strconv.ParseUint(current.ResourceVersion, 10, 64)
	if err != nil {
		return err
	}
	secret = secret.DeepCopy()
	secret.ResourceVersion = strconv.FormatUint(version+1, 10)
	return c.write(namespace, secret)
}

func (c *fakeKubeClient) write(namespace string, secret *corev1.Secret) error {
	data, err := json.Marshal(secret)
	if err != nil {
		return err
	}
	path := c.makePath(namespace, secret.Name)
	if err := os.WriteFile(path+".tmp", data, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func (c *fakeKubeClient) listSecrets(ctx context.Context, namespace string, opts metav1.ListOptions) (*corev1.SecretList, error) {
	selector, err := labels.Parse(opts.LabelSelector)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(c.sealDir)
	if err != nil {
		return nil, err
	}
	result := &corev1.SecretList{}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), namespace+"-") || strings.HasSuffix(entry.Name(), ".tmp") {
			continue
		}
		secret, err := c.getSecret(ctx, namespace, strings.TrimPrefix(entry.Name(), namespace+"-"))
		if k8serrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if selector.Matches(labels.Set(secret.Labels)) {
			result.Items = append(result.Items, *secret)
		}
	}
	return result, nil
}

func (c *fakeKubeClient) deleteSecret(ctx context.Context, namespace, name string, uid types.UID) error {
	lock := flock.New(filepath.Join(c.sealDir, ".state-lock"))
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Close()
	secret, err := c.getSecret(ctx, namespace, name)
	if err != nil {
		return err
	}
	if secret.UID != uid {
		return k8serrors.NewConflict(schema.GroupResource{Resource: "secrets"}, name, errors.New("UID mismatch"))
	}
	return os.Remove(c.makePath(namespace, name))
}

func (c *fakeKubeClient) makePath(namespace, name string) string {
	return filepath.Join(c.sealDir, namespace+"-"+name)
}
