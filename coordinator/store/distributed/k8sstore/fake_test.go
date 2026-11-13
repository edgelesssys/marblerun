//go:build fakestore

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package k8sstore

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
)

func TestFileBackedChunksSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	c := NewWithFakeK8s("test", "state", dir, zaptest.NewLogger(t))
	t.Cleanup(func() { waitForGC(c) })
	state := loadTestState(t, c)
	state.SealedData = bytes.Repeat([]byte("persistent"), corev1.MaxSecretSize/10+1)
	state.SealedKey = []byte("wrapped key")
	require.NoError(t, c.SaveState(t.Context(), state))
	restarted := NewWithFakeK8s("test", "state", dir, zaptest.NewLogger(t))
	t.Cleanup(func() { waitForGC(restarted) })
	loaded := loadTestState(t, restarted)
	require.Equal(t, state.SealedData, loaded.SealedData)
	require.Equal(t, state.SealedKey, loaded.SealedKey)
	competing := loadTestState(t, c)
	loaded.SealedData = []byte("new state")
	require.NoError(t, restarted.SaveState(t.Context(), loaded))
	require.ErrorContains(t, c.SaveState(t.Context(), competing), "newer version")
	current := loadTestState(t, c)
	collectTestState(t, c, current.StateRef.(*corev1.Secret))
	require.Equal(t, loaded.SealedData, loadTestState(t, restarted).SealedData)
}
