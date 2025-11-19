//go:build fakestore

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package seal

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
)

// NewWithFakeK8s creates a new Sealer with a fake kube client backed by files in sealDir.
func NewWithFakeK8s(sealer seal.Sealer, configMapName, namespace, sealDir string, log *zap.Logger) (*Sealer, error) {
	keyHandler, err := newK8sKeyHandler(&fakeKubeClient{sealDir: sealDir}, configMapName, namespace, log)
	if err != nil {
		return nil, err
	}

	return &Sealer{
		Sealer:             sealer,
		keyHandler:         keyHandler,
		sealWithProductKey: ecrypto.SealWithProductKey256,
		sealWithUniqueKey:  ecrypto.SealWithUniqueKey256,
		unseal:             ecrypto.Unseal256,
		unsealFallBack:     ecrypto.Unseal,
		log:                log,
	}, nil
}

type fakeKubeClient struct {
	sealDir string
}

// createConfigMap creates a new ConfigMap.
func (c *fakeKubeClient) createConfigMap(_ context.Context, _ string, _ *corev1.ConfigMap) error {
	panic("not implemented")
}

// getConfigMap retrieves a ConfigMap.
func (c *fakeKubeClient) getConfigMap(_ context.Context, _, _ string) (*corev1.ConfigMap, error) {
	cfg := &corev1.ConfigMap{BinaryData: make(map[string][]byte)}
	data, err := os.ReadFile(c.getPath())
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	} else if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// patchConfigMapKey patches a single key in a ConfigMap.
func (c *fakeKubeClient) patchConfigMapKey(ctx context.Context, namespace, name string, patch []byte) error {
	cfg, err := c.getConfigMap(ctx, namespace, name)
	if err != nil {
		return err
	}
	var patches []patchByteValue
	if err := json.Unmarshal(patch, &patches); err != nil {
		return err
	}
	cfg.BinaryData[patches[0].Path[len("/binaryData/"):]] = patches[0].Value
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(c.getPath(), data, 0o644)
}

func (c *fakeKubeClient) getPath() string {
	return filepath.Join(c.sealDir, "sealed_key") // to be compatible with test recovery trigger
}
