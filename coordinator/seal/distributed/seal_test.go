/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package seal

import (
	"bytes"
	"context"
	"testing"

	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestExportKeyEncryptionKey(t *testing.T) {
	testCases := map[string]struct {
		keyHandler  *stubKeyHandler
		sealingFunc sealFunc
		kek         []byte
		wantErr     bool
	}{
		"success": {
			keyHandler:  &stubKeyHandler{},
			sealingFunc: fakeSealingFunc,
			kek:         []byte("kek"),
		},
		"kek not set": {
			keyHandler:  &stubKeyHandler{},
			sealingFunc: fakeSealingFunc,
			wantErr:     true,
		},
		"sealWithProductKey fails": {
			keyHandler: &stubKeyHandler{},
			sealingFunc: func(_, _ []byte) ([]byte, error) {
				return nil, assert.AnError
			},
			kek:     []byte("kek"),
			wantErr: true,
		},
		"setKey fails": {
			keyHandler: &stubKeyHandler{
				setKeyErr: assert.AnError,
			},
			sealingFunc: fakeSealingFunc,
			kek:         []byte("kek"),
			wantErr:     true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			s := &Sealer{
				keyHandler:         tc.keyHandler,
				sealWithProductKey: tc.sealingFunc,
				mode:               seal.ModeProductKey,
				keyEncryptionKey:   tc.kek,
				log:                zaptest.NewLogger(t),
			}

			got, err := s.ExportKeyEncryptionKey(context.Background())
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Equal(tc.kek, got)
			// fakeSealingFunc xors the key with 0xFF,
			// run it again to get the original key
			kek, err := fakeSealingFunc(tc.keyHandler.setKeyVal, nil)
			require.NoError(t, err)
			assert.Equal(tc.kek, kek)
		})
	}
}

func TestSetKeyEncryptionKey(t *testing.T) {
	testCases := map[string]struct {
		keyHandler  *stubKeyHandler
		sealingFunc sealFunc
		kek         []byte
		wantErr     bool
	}{
		"success": {
			keyHandler:  &stubKeyHandler{},
			sealingFunc: fakeSealingFunc,
			kek:         []byte("kek"),
		},
		"sealWithProductKey fails": {
			keyHandler: &stubKeyHandler{},
			sealingFunc: func(_, _ []byte) ([]byte, error) {
				return nil, assert.AnError
			},
			kek:     []byte("kek"),
			wantErr: true,
		},
		"setKey fails": {
			keyHandler: &stubKeyHandler{
				setKeyErr: assert.AnError,
			},
			sealingFunc: fakeSealingFunc,
			kek:         []byte("kek"),
			wantErr:     true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			s := &Sealer{
				keyHandler:         tc.keyHandler,
				sealWithProductKey: tc.sealingFunc,
				mode:               seal.ModeProductKey,
				log:                zaptest.NewLogger(t),
			}

			err := s.SetKeyEncryptionKey(context.Background(), tc.kek)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Equal(tc.kek, s.keyEncryptionKey)
			// fakeSealingFunc xors the key with 0xFF,
			// run it again to get the original key
			kek, err := fakeSealingFunc(tc.keyHandler.setKeyVal, nil)
			require.NoError(t, err)
			assert.Equal(tc.kek, kek)
		})
	}
}

func TestUnsealEncryptionKey(t *testing.T) {
	require := require.New(t)
	testDEK, err := seal.GenerateEncryptionKey()
	require.NoError(err)
	testKEK, err := seal.GenerateEncryptionKey()
	require.NoError(err)
	testSealedKEK, err := fakeSealingFunc(testKEK, nil)
	require.NoError(err)
	testEncryptedDEK, err := ecrypto.Encrypt(testDEK, testKEK, nil)
	require.NoError(err)

	testCases := map[string]struct {
		keyHandler     *stubKeyHandler
		unsealFunc     func([]byte, []byte) ([]byte, error)
		unsealFallBack func([]byte, []byte) ([]byte, error)
		encryptedKey   []byte
		kek            []byte
		wantErr        bool
	}{
		"success": {
			encryptedKey: testEncryptedDEK,
			kek:          testKEK,
		},
		"kek not set, load from remote": {
			keyHandler: &stubKeyHandler{
				getKeyVal: testSealedKEK,
			},
			unsealFunc:   fakeUnsealFunc,
			encryptedKey: testEncryptedDEK,
		},
		"unsealWithProductKey fails": {
			keyHandler: &stubKeyHandler{
				getKeyVal: testKEK,
			},
			unsealFunc: func(_, _ []byte) ([]byte, error) {
				return nil, assert.AnError
			},
			unsealFallBack: func(_, _ []byte) ([]byte, error) {
				return nil, assert.AnError
			},
			encryptedKey: testEncryptedDEK,
			wantErr:      true,
		},
		"unsealWithProductKey succeeds with fallback": {
			keyHandler: &stubKeyHandler{
				getKeyVal: testSealedKEK,
			},
			unsealFunc: func(_, _ []byte) ([]byte, error) {
				return nil, assert.AnError
			},
			unsealFallBack: fakeUnsealFunc,
			encryptedKey:   testEncryptedDEK,
		},
		"getKey fails": {
			keyHandler: &stubKeyHandler{
				getKeyErr: assert.AnError,
			},
			unsealFunc:   fakeUnsealFunc,
			encryptedKey: testEncryptedDEK,
			wantErr:      true,
		},
		"invalid kek": {
			encryptedKey: testEncryptedDEK,
			kek:          []byte("invalid"),
			wantErr:      true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			s := &Sealer{
				keyHandler:       tc.keyHandler,
				unseal:           tc.unsealFunc,
				unsealFallBack:   tc.unsealFallBack,
				keyEncryptionKey: tc.kek,
				log:              zaptest.NewLogger(t),
			}

			got, err := s.UnsealEncryptionKey(tc.encryptedKey, nil)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Equal(testDEK, got)
		})
	}
}

func TestSealEncryptionKey(t *testing.T) {
	testCases := map[string]struct {
		kek []byte
	}{
		"uses preset kek": {
			kek: bytes.Repeat([]byte{0x1}, 16),
		},
		"generates new kek": {
			kek: nil,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			s := &Sealer{
				encryptionKey:    []byte("key"),
				keyEncryptionKey: tc.kek,
				log:              zaptest.NewLogger(t),
			}

			additionalData := []byte("additionalData")
			sealed, err := s.SealEncryptionKey(additionalData, seal.ModeDisabled)
			assert.NoError(err)
			_, err = ecrypto.Decrypt(sealed, s.keyEncryptionKey, additionalData)
			assert.NoError(err)
			if tc.kek != nil {
				assert.Equal(tc.kek, s.keyEncryptionKey)
			}
		})
	}
}

func TestSealKEK(t *testing.T) {
	testCases := map[string]struct {
		keyHandler         *stubKeyHandler
		sealWithProductKey sealFunc
		sealWithUniqueKey  sealFunc
		mode               seal.Mode
		wantErr            bool
	}{
		"product key": {
			keyHandler:         &stubKeyHandler{},
			sealWithProductKey: fakeSealingFunc,
			mode:               seal.ModeProductKey,
		},
		"unique key": {
			keyHandler:        &stubKeyHandler{},
			sealWithUniqueKey: fakeSealingFunc,
			mode:              seal.ModeUniqueKey,
		},
		"ModeDisabled uses unique key": {
			keyHandler:        &stubKeyHandler{},
			sealWithUniqueKey: fakeSealingFunc,
			mode:              seal.ModeDisabled,
		},
		"sealWithProductKey fails": {
			keyHandler: &stubKeyHandler{},
			sealWithProductKey: func(_, _ []byte) ([]byte, error) {
				return nil, assert.AnError
			},
			mode:    seal.ModeProductKey,
			wantErr: true,
		},
		"setKey fails": {
			keyHandler: &stubKeyHandler{
				setKeyErr: assert.AnError,
			},
			sealWithProductKey: fakeSealingFunc,
			mode:               seal.ModeProductKey,
			wantErr:            true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			kek := []byte("kek")

			s := &Sealer{
				keyHandler:         tc.keyHandler,
				sealWithProductKey: tc.sealWithProductKey,
				sealWithUniqueKey:  tc.sealWithUniqueKey,
				keyEncryptionKey:   kek,
				log:                zaptest.NewLogger(t),
			}

			err := s.SealKEK(context.Background(), tc.mode)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tc.mode, s.mode)
			// fakeSealingFunc xors the key with 0xFF,
			// run it again to get the original key
			gotKek, err := fakeSealingFunc(tc.keyHandler.setKeyVal, nil)
			require.NoError(err)
			assert.Equal(kek, gotKek)
		})
	}
}

func TestGetKey(t *testing.T) {
	keyID := "key-id"
	testValue := []byte("key")

	testCases := map[string]struct {
		kubectl *stubKubectl
		wantErr bool
	}{
		"success": {
			kubectl: &stubKubectl{
				getVal: &corev1.ConfigMap{
					BinaryData: map[string][]byte{
						keyID: testValue,
					},
				},
			},
		},
		"no key": {
			kubectl: &stubKubectl{
				getVal: &corev1.ConfigMap{},
			},
			wantErr: true,
		},
		"get fails": {
			kubectl: &stubKubectl{
				getErr: assert.AnError,
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			s := &k8sKeyHandler{
				client: tc.kubectl,
				keyID:  keyID,
				log:    zaptest.NewLogger(t),
			}

			got, err := s.getKey(context.Background())
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Equal(testValue, got)
		})
	}
}

func TestSetKey(t *testing.T) {
	testCases := map[string]struct {
		kubeClient          *stubKubectl
		wantCreate          bool
		wantBinaryDataPatch bool
		wantErr             bool
	}{
		"success": {
			kubeClient: &stubKubectl{
				getVal: &corev1.ConfigMap{
					BinaryData: map[string][]byte{},
				},
			},
		},
		"map doesnt exist yet": {
			kubeClient: &stubKubectl{
				getErr: k8serrors.NewNotFound(schema.GroupResource{}, ""),
			},
			wantCreate: true,
		},
		"map exists, but no binary data": {
			kubeClient: &stubKubectl{
				getVal: &corev1.ConfigMap{},
			},
			wantBinaryDataPatch: true,
		},
		"get error": {
			kubeClient: &stubKubectl{
				getErr: assert.AnError,
			},
			wantErr: true,
		},
		"patch error": {
			kubeClient: &stubKubectl{
				getVal: &corev1.ConfigMap{
					BinaryData: map[string][]byte{},
				},
				patchErr: assert.AnError,
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			s := &k8sKeyHandler{
				client: tc.kubeClient,
				log:    zaptest.NewLogger(t),
			}

			key := []byte("new-key-encryption-key")
			err := s.setKey(context.Background(), key)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)

			if tc.wantCreate {
				assert.True(tc.kubeClient.createCalled)
			} else {
				assert.False(tc.kubeClient.createCalled)
			}

			if tc.wantBinaryDataPatch {
				assert.Contains(string(tc.kubeClient.patchVal), `{"op":"add","path":"/binaryData","value":{}}`)
			} else {
				assert.NotContains(string(tc.kubeClient.patchVal), `{"op":"add","path":"/binaryData","value":{}}`)
			}
		})
	}
}

type stubKeyHandler struct {
	getKeyVal []byte
	getKeyErr error

	setKeyVal []byte
	setKeyErr error
}

func (s *stubKeyHandler) getKey(_ context.Context) ([]byte, error) {
	return s.getKeyVal, s.getKeyErr
}

func (s *stubKeyHandler) setKey(_ context.Context, key []byte) error {
	s.setKeyVal = key
	return s.setKeyErr
}

func fakeSealingFunc(key, _ []byte) ([]byte, error) {
	sealedKey := make([]byte, len(key))
	for i := range key {
		sealedKey[i] = key[i] ^ 0xAB
	}
	return sealedKey, nil
}

func fakeUnsealFunc(key, _ []byte) ([]byte, error) {
	unsealedKey := make([]byte, len(key))
	for i := range key {
		unsealedKey[i] = key[i] ^ 0xAB
	}
	return unsealedKey, nil
}

type stubKubectl struct {
	createCalled bool
	createErr    error
	getVal       *corev1.ConfigMap
	getErr       error
	patchVal     []byte
	patchErr     error
}

func (s *stubKubectl) createConfigMap(_ context.Context, _ string, _ *corev1.ConfigMap) error {
	s.createCalled = true
	return s.createErr
}

func (s *stubKubectl) getConfigMap(_ context.Context, _, _ string) (*corev1.ConfigMap, error) {
	return s.getVal, s.getErr
}

func (s *stubKubectl) patchConfigMapKey(_ context.Context, _, _ string, patch []byte) error {
	s.patchVal = patch
	return s.patchErr
}
