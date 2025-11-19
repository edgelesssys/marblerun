/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package k8sstore

import (
	"context"
	"errors"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/store/distributed/transaction"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestGetState(t *testing.T) {
	someErr := errors.New("failed")

	testCases := map[string]struct {
		kubectl      *stubKubeClient
		wantCreation bool
		wantErr      bool
	}{
		"secret exists": {
			kubectl: &stubKubeClient{
				secret: &corev1.Secret{},
			},
		},
		"secret does not exist": {
			kubectl: &stubKubeClient{
				getErr: k8serrors.NewNotFound(schema.GroupResource{}, ""),
			},
			wantCreation: true,
		},
		"error getting secret": {
			kubectl: &stubKubeClient{
				getErr: someErr,
			},
			wantErr: true,
		},
		"error creating secret": {
			kubectl: &stubKubeClient{
				getErr:    k8serrors.NewNotFound(schema.GroupResource{}, ""),
				createErr: someErr,
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			cl := &Client{
				client: tc.kubectl,
				log:    zaptest.NewLogger(t),
			}

			_, err := cl.GetState(context.Background())
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Equal(tc.wantCreation, tc.kubectl.createdSecret != nil)
		})
	}
}

func TestSaveState(t *testing.T) {
	someErr := errors.New("failed")

	testCases := map[string]struct {
		kubectl *stubKubeClient
		state   *transaction.State
		wantErr bool
	}{
		"success": {
			kubectl: &stubKubeClient{
				secret: &corev1.Secret{},
			},
			state: &transaction.State{StateRef: &corev1.Secret{}},
		},
		"error updating secret": {
			kubectl: &stubKubeClient{
				updateErr: someErr,
			},
			state:   &transaction.State{StateRef: &corev1.Secret{}},
			wantErr: true,
		},
		"invalid state ref": {
			kubectl: &stubKubeClient{
				secret: &corev1.Secret{},
			},
			state:   &transaction.State{StateRef: map[string]byte{}},
			wantErr: true,
		},
		"update conflict": {
			kubectl: &stubKubeClient{
				updateErr: k8serrors.NewConflict(schema.GroupResource{}, "", nil),
			},
			state:   &transaction.State{StateRef: &corev1.Secret{}},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			cl := &Client{
				client: tc.kubectl,
				log:    zaptest.NewLogger(t),
			}

			err := cl.SaveState(context.Background(), tc.state)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
		})
	}
}

type stubKubeClient struct {
	secret        *corev1.Secret
	createdSecret *corev1.Secret
	createErr     error
	getErr        error
	updateErr     error
}

func (s *stubKubeClient) createSecret(_ context.Context, _ string, secret *corev1.Secret) (*corev1.Secret, error) {
	s.createdSecret = secret
	return secret, s.createErr
}

func (s *stubKubeClient) getSecret(_ context.Context, _ string, _ string) (*corev1.Secret, error) {
	return s.secret, s.getErr
}

func (s *stubKubeClient) updateSecret(_ context.Context, _ string, secret *corev1.Secret) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	s.secret = secret
	return nil
}
