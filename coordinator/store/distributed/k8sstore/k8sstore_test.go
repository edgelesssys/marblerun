/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package k8sstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/edgelesssys/marblerun/coordinator/store/distributed/transaction"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/flowcontrol"
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

func (s *stubKubeClient) listSecrets(context.Context, string, metav1.ListOptions) (*corev1.SecretList, error) {
	return &corev1.SecretList{}, nil
}

func (s *stubKubeClient) deleteSecret(context.Context, string, string, types.UID) error {
	return nil
}

func TestLazyMigration(t *testing.T) {
	ctx := t.Context()
	c, api := testClient(t)
	c.chunking = false
	state, err := c.GetState(ctx)
	require.NoError(t, err)
	// The wrapped key shares the budget; wire-format base64 does not.
	state.SealedKey = []byte("wrapped-key")
	state.SealedData = bytes.Repeat([]byte{0x5a}, corev1.MaxSecretSize-len(state.SealedKey))
	require.NoError(t, c.SaveState(ctx, state))
	state, err = c.GetState(ctx)
	require.NoError(t, err)
	inline := state.StateRef.(*corev1.Secret)
	require.NotContains(t, inline.Data, descriptorKey)
	require.Equal(t, "1", inline.Annotations[revisionAnnotation])
	state.SealedData = append(state.SealedData, 0x17)
	require.ErrorContains(t, c.SaveState(ctx, state), "enable coordinator.chunkedState")
	c.chunking = true
	require.NoError(t, c.SaveState(ctx, state))
	// Save must not mutate the reference used by the caller's transaction.
	require.NotContains(t, inline.Data, descriptorKey)
	loaded, err := c.GetState(ctx)
	require.NoError(t, err)
	require.Equal(t, state.SealedData, loaded.SealedData)
	require.Equal(t, state.SealedKey, loaded.SealedKey)
	require.Equal(t, "2", loaded.StateRef.(*corev1.Secret).Annotations[revisionAnnotation])
	require.NotContains(t, loaded.StateRef.(*corev1.Secret).Data, stdstore.SealedDataFname)
	// The gate controls only the first transition. Shrinking never goes inline.
	c.chunking = false
	loaded.SealedData = []byte("small state after migration")
	require.NoError(t, c.SaveState(ctx, loaded))
	got, err := c.GetState(ctx)
	require.NoError(t, err)
	require.Equal(t, loaded.SealedData, got.SealedData)
	require.Contains(t, got.StateRef.(*corev1.Secret).Data, descriptorKey)
	require.Equal(t, "3", got.StateRef.(*corev1.Secret).Annotations[revisionAnnotation])
	all, err := api.CoreV1().Secrets(c.namespace).List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	for _, item := range all.Items {
		require.LessOrEqual(t, secretDataSize(&item), corev1.MaxSecretSize)
	}
}

func TestCompetingChunkWriters(t *testing.T) {
	c, _ := testClient(t)
	a := loadTestState(t, c)
	b := loadTestState(t, c)
	a.SealedData = bytes.Repeat([]byte("a"), corev1.MaxSecretSize+7)
	a.SealedKey = []byte("key-a")
	b.SealedData = bytes.Repeat([]byte("b"), corev1.MaxSecretSize+13)
	b.SealedKey = []byte("key-b")
	require.NoError(t, c.SaveState(t.Context(), a))
	require.ErrorContains(t, c.SaveState(t.Context(), b), "newer version")
	got := loadTestState(t, c)
	require.Equal(t, a.SealedData, got.SealedData)
	require.Equal(t, a.SealedKey, got.SealedKey)
	require.Equal(t, "1", got.StateRef.(*corev1.Secret).Annotations[revisionAnnotation])
}

func TestInterruptedChunkPublication(t *testing.T) {
	for _, failure := range []string{"upload", "head", "ambiguous head"} {
		t.Run(failure, func(t *testing.T) {
			c, api := testClient(t)
			state := loadTestState(t, c)
			state.SealedData, state.SealedKey = []byte("previous"), []byte("old-key")
			require.NoError(t, c.SaveState(t.Context(), state))
			state = loadTestState(t, c)
			state.SealedData = bytes.Repeat([]byte("new"), corev1.MaxSecretSize/3+12)
			state.SealedKey = []byte("new-key")
			if failure == "upload" {
				api.PrependReactor("create", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
					s := a.(k8stesting.CreateAction).GetObject().(*corev1.Secret)
					if s.Labels[indexLabel] == "1" {
						return true, nil, errors.New("upload interrupted")
					}
					return false, nil, nil
				})
			} else {
				api.PrependReactor("update", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
					if failure == "ambiguous head" {
						require.NoError(t, api.Tracker().Update(a.GetResource(), a.(k8stesting.UpdateAction).GetObject(), c.namespace))
					}
					return true, nil, errors.New("connection lost")
				})
			}
			err := c.SaveState(t.Context(), state)
			got := loadTestState(t, c)
			if failure == "ambiguous head" {
				require.NoError(t, err)
				require.Equal(t, state.SealedData, got.SealedData)
				require.Equal(t, state.SealedKey, got.SealedKey)
			} else {
				require.Error(t, err)
				require.Equal(t, []byte("previous"), got.SealedData)
				require.Equal(t, []byte("old-key"), got.SealedKey)
			}
		})
	}
}

func TestChunkIntegrity(t *testing.T) {
	for _, damage := range []string{"missing", "digest", "owner", "version", "size", "mixed layout", "revision", "overflow"} {
		t.Run(damage, func(t *testing.T) {
			c, api := testClient(t)
			state := loadTestState(t, c)
			state.SealedData = bytes.Repeat([]byte("data"), corev1.MaxSecretSize/4+1)
			require.NoError(t, c.SaveState(t.Context(), state))
			head := loadTestState(t, c).StateRef.(*corev1.Secret)
			var d descriptor
			require.NoError(t, json.Unmarshal(head.Data[descriptorKey], &d))
			resource := corev1.SchemeGroupVersion.WithResource("secrets")
			switch damage {
			case "missing":
				require.NoError(t, api.Tracker().Delete(resource, c.namespace, chunkName(head, &d, 0)))
			case "digest", "owner":
				chunk, err := api.CoreV1().Secrets(c.namespace).Get(t.Context(), chunkName(head, &d, 0), metav1.GetOptions{})
				require.NoError(t, err)
				if damage == "digest" {
					chunk.Data["chunk"][0] ^= 0xff
				} else {
					chunk.OwnerReferences[0].UID = "another-head"
				}
				require.NoError(t, api.Tracker().Update(resource, chunk, c.namespace))
			default:
				switch damage {
				case "version":
					d.Version = 2
				case "size":
					d.Size = maxStateSize + 1
				case "mixed layout":
					head.Data[stdstore.SealedDataFname] = []byte("inline")
				case "revision":
					head.Annotations[revisionAnnotation] = "broken"
				case "overflow":
					head.Annotations[revisionAnnotation] = strconv.FormatUint(^uint64(0), 10)
					d.Revision = ^uint64(0)
				}
				raw, err := json.Marshal(d)
				require.NoError(t, err)
				head.Data[descriptorKey] = raw
				require.NoError(t, api.Tracker().Update(resource, head, c.namespace))
			}
			if damage == "overflow" {
				require.ErrorContains(t, c.SaveState(t.Context(), &transaction.State{StateRef: head}), "overflow")
			} else {
				_, err := c.GetState(t.Context())
				require.Error(t, err)
			}
		})
	}
}

func TestCollectionFencesUploads(t *testing.T) {
	for _, publishBeforeBarrier := range []bool{false, true} {
		t.Run(fmt.Sprint(publishBeforeBarrier), func(t *testing.T) {
			c, api := testClient(t)
			state := loadTestState(t, c)
			state.SealedData = bytes.Repeat([]byte("initial"), corev1.MaxSecretSize/7+1)
			require.NoError(t, c.SaveState(t.Context(), state))
			old := loadTestState(t, c)
			writer := loadTestState(t, c)
			writer.SealedData = []byte("new committed state")
			triggered := false
			backend := c.client
			c.client = &updateHookClient{kubectl: backend, update: func(ctx context.Context, namespace string, s *corev1.Secret) error {
				if triggered || s.Annotations[gcBarrierAnnotation] != "" {
					return backend.updateSecret(ctx, namespace, s)
				}
				triggered = true
				if publishBeforeBarrier {
					require.NoError(t, backend.updateSecret(ctx, namespace, s))
				}
				require.NoError(t, c.collect(t.Context(), old.StateRef.(*corev1.Secret), time.Now().Add(time.Hour)))
				if publishBeforeBarrier {
					return nil
				}
				return backend.updateSecret(ctx, namespace, s)
			}}
			err := c.SaveState(t.Context(), writer)
			got := loadTestState(t, c)
			if publishBeforeBarrier {
				require.NoError(t, err)
				require.Equal(t, writer.SealedData, got.SealedData)
			} else {
				require.ErrorContains(t, err, "newer version")
				require.Equal(t, old.SealedData, got.SealedData)
			}
			// Collect again to remove the previously protected snapshot, if superseded.
			require.NoError(t, c.collect(t.Context(), got.StateRef.(*corev1.Secret), time.Now().Add(time.Hour)))
			chunks, err := api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: headLabel})
			require.NoError(t, err)
			var d descriptor
			require.NoError(t, json.Unmarshal(got.StateRef.(*corev1.Secret).Data[descriptorKey], &d))
			require.Len(t, chunks.Items, d.Count)
			for _, chunk := range chunks.Items {
				require.Equal(t, d.Upload, chunk.Labels[uploadLabel])
			}
		})
	}
}

func TestReaderRetriesCollectedSnapshot(t *testing.T) {
	c, api := testClient(t)
	state := loadTestState(t, c)
	state.SealedData = bytes.Repeat([]byte("old"), corev1.MaxSecretSize/3+1)
	require.NoError(t, c.SaveState(t.Context(), state))
	old := loadTestState(t, c)
	updated := loadTestState(t, c)
	updated.SealedData, updated.SealedKey = []byte("new"), []byte("matching key")
	require.NoError(t, c.SaveState(t.Context(), updated))
	current := loadTestState(t, c)
	require.NoError(t, c.collect(t.Context(), current.StateRef.(*corev1.Secret), time.Now().Add(time.Hour)))
	first := true
	api.PrependReactor("get", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if first && a.(k8stesting.GetAction).GetName() == c.secretName {
			first = false
			return true, old.StateRef.(*corev1.Secret).DeepCopy(), nil
		}
		return false, nil, nil
	})
	got := loadTestState(t, c)
	require.Equal(t, updated.SealedData, got.SealedData)
	require.Equal(t, updated.SealedKey, got.SealedKey)
}

func TestAutomaticCollectionAfterFailedMigration(t *testing.T) {
	c, api := testClient(t)
	state := loadTestState(t, c)
	state.SealedData = []byte("inline state")
	require.NoError(t, c.SaveState(t.Context(), state))
	state = loadTestState(t, c)
	state.SealedData = bytes.Repeat([]byte("x"), corev1.MaxSecretSize+1)
	api.PrependReactor("create", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.(k8stesting.CreateAction).GetObject().(*corev1.Secret).Labels[indexLabel] == "1" {
			return true, nil, errors.New("interrupted upload")
		}
		return false, nil, nil
	})
	require.Error(t, c.SaveState(t.Context(), state))
	c.nextGC = time.Time{}
	got := loadTestState(t, c)
	require.Equal(t, []byte("inline state"), got.SealedData)
	chunks, err := api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: headLabel})
	require.NoError(t, err)
	require.Len(t, chunks.Items, 1, "young upload must be retained")
	chunk := chunks.Items[0].DeepCopy()
	chunk.CreationTimestamp = metav1.NewTime(time.Now().Add(-time.Hour))
	require.NoError(t, api.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), chunk, c.namespace))
	c.nextGC = time.Time{}
	got = loadTestState(t, c)
	require.Equal(t, []byte("inline state"), got.SealedData)
	require.Equal(t, "1", got.StateRef.(*corev1.Secret).Annotations[revisionAnnotation])
	chunks, err = api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: headLabel})
	require.NoError(t, err)
	require.Empty(t, chunks.Items)
	got.SealedData = []byte("post-GC commit")
	require.NoError(t, c.SaveState(t.Context(), got), "GetState must return the post-barrier resourceVersion")
}

func TestCollectionDoesNotFollowReplacedHead(t *testing.T) {
	c, api := testClient(t)
	state := loadTestState(t, c)
	state.SealedData = bytes.Repeat([]byte("x"), corev1.MaxSecretSize+1)
	require.NoError(t, c.SaveState(t.Context(), state))
	old := loadTestState(t, c).StateRef.(*corev1.Secret)
	state = loadTestState(t, c)
	state.SealedData = []byte("current")
	require.NoError(t, c.SaveState(t.Context(), state))
	current := loadTestState(t, c).StateRef.(*corev1.Secret)
	current.UID = types.UID(uuid.NewString())
	require.NoError(t, api.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), current, c.namespace))
	require.ErrorContains(t, c.collect(t.Context(), old, time.Now().Add(time.Hour)), "replaced")
	chunks, err := api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: headLabel})
	require.NoError(t, err)
	require.Len(t, chunks.Items, 4, "no chunks may be deleted after a head UID change")
}

func TestCollectionDuringUpload(t *testing.T) {
	c, api := testClient(t)
	state := loadTestState(t, c)
	state.SealedData = []byte("committed inline state")
	require.NoError(t, c.SaveState(t.Context(), state))
	state = loadTestState(t, c)
	state.SealedData = bytes.Repeat([]byte("x"), corev1.MaxSecretSize+1)
	backend := c.client
	c.client = &createHookClient{kubectl: backend, create: func(ctx context.Context, namespace string, s *corev1.Secret) (*corev1.Secret, error) {
		if s.Labels[indexLabel] == "1" {
			// The first chunk exists, but later chunks have not been created yet.
			require.NoError(t, c.collect(ctx, state.StateRef.(*corev1.Secret), time.Now().Add(time.Hour)))
		}
		return backend.createSecret(ctx, namespace, s)
	}}
	require.ErrorContains(t, c.SaveState(t.Context(), state), "newer version")
	got := loadTestState(t, c)
	require.Equal(t, []byte("committed inline state"), got.SealedData)
	chunks, err := api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: headLabel})
	require.NoError(t, err)
	require.Len(t, chunks.Items, 2, "late chunks are orphans, never published")
	require.NoError(t, c.collect(t.Context(), got.StateRef.(*corev1.Secret), time.Now().Add(time.Hour)))
	chunks, err = api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: headLabel})
	require.NoError(t, err)
	require.Empty(t, chunks.Items)
}

func TestOverlappingCollectors(t *testing.T) {
	c, api := testClient(t)
	state := loadTestState(t, c)
	state.SealedData = bytes.Repeat([]byte("x"), corev1.MaxSecretSize+1)
	require.NoError(t, c.SaveState(t.Context(), state))
	state = loadTestState(t, c)
	state.SealedData = []byte("current state")
	require.NoError(t, c.SaveState(t.Context(), state))
	head := loadTestState(t, c).StateRef.(*corev1.Secret)
	backend := c.client
	other := &Client{client: backend, namespace: c.namespace, secretName: c.secretName, log: zaptest.NewLogger(t)}
	c.client = &updateHookClient{kubectl: backend, update: func(ctx context.Context, namespace string, s *corev1.Secret) error {
		err := backend.updateSecret(ctx, namespace, s)
		if err == nil {
			// Another collector completes after our barrier but before our deletes.
			require.NoError(t, other.collect(ctx, head, time.Now().Add(time.Hour)))
		}
		return err
	}}
	require.NoError(t, c.collect(t.Context(), head, time.Now().Add(time.Hour)))
	got := loadTestState(t, c)
	require.Equal(t, state.SealedData, got.SealedData)
	require.Equal(t, "2", got.StateRef.(*corev1.Secret).Annotations[revisionAnnotation])
	chunks, err := api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: headLabel})
	require.NoError(t, err)
	require.Len(t, chunks.Items, 1)
}

func TestCollectionProgressAtProductionRate(t *testing.T) {
	c, api := testClient(t)
	state := loadTestState(t, c)
	state.SealedData = bytes.Repeat([]byte{0x71}, maxStateSize)
	require.NoError(t, c.SaveState(t.Context(), state))
	base := c.client
	limiter := flowcontrol.NewTokenBucketRateLimiter(rest.DefaultQPS, rest.DefaultBurst)
	defer limiter.Stop()
	limited := &limitedGCClient{kubectl: base, limiter: limiter}
	for revision := range 3 {
		// Retire one maximum-size snapshot each interval. Backdate its chunks
		// rather than waiting for the ten-minute retention grace in this test.
		chunks, err := api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: headLabel})
		require.NoError(t, err)
		require.Len(t, chunks.Items, 32)
		for _, chunk := range chunks.Items {
			chunk.CreationTimestamp = metav1.NewTime(time.Now().Add(-time.Hour))
			require.NoError(t, api.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), &chunk, c.namespace))
		}
		state = loadTestState(t, c)
		state.SealedData[0] = byte(revision)
		require.NoError(t, c.SaveState(t.Context(), state))
		head := loadTestState(t, c).StateRef.(*corev1.Secret)
		c.client = limited
		c.nextGC = time.Time{}
		// Start with an empty bucket, as after a large state upload.
		for limiter.TryAccept() {
		}
		if revision == 0 {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			require.True(t, c.maybeCollect(ctx, head))
			cancel()
			remaining, err := api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: headLabel})
			require.NoError(t, err)
			require.Greater(t, len(remaining.Items), 32)
			require.Less(t, len(remaining.Items), 64, "deadline must interrupt after partial progress")
			assert.LessOrEqual(t, time.Until(c.nextGC), 10*time.Second)
			c.nextGC = time.Time{} // Advance to the next eligible operation.
		}
		require.True(t, c.maybeCollect(t.Context(), head))
		chunks, err = api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: headLabel})
		require.NoError(t, err)
		require.Equal(t, 32, len(chunks.Items), "each interval must reclaim the entire retired snapshot")
		c.client = base
		got := loadTestState(t, c)
		require.Equal(t, state.SealedData, got.SealedData)
		require.Equal(t, state.SealedKey, got.SealedKey)
	}
}

func TestCollectionResumesFullBatch(t *testing.T) {
	c, api := testClient(t)
	state := loadTestState(t, c)
	state.SealedData = bytes.Repeat([]byte{1}, corev1.MaxSecretSize+1)
	require.NoError(t, c.SaveState(t.Context(), state))
	chunks, err := api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: headLabel})
	require.NoError(t, err)
	for i := range gcBatchSize + 1 {
		chunk := chunks.Items[0].DeepCopy()
		chunk.Name = fmt.Sprintf("abandoned-%d", i)
		chunk.Labels[uploadLabel] = uuid.NewString()
		chunk.CreationTimestamp = metav1.NewTime(time.Now().Add(-time.Hour))
		require.NoError(t, api.Tracker().Create(corev1.SchemeGroupVersion.WithResource("secrets"), chunk, c.namespace))
	}
	limiter := flowcontrol.NewTokenBucketRateLimiter(rest.DefaultQPS, rest.DefaultBurst)
	defer limiter.Stop()
	c.client = &limitedGCClient{kubectl: c.client, limiter: limiter}
	c.nextGC = time.Time{}
	got := loadTestState(t, c)
	require.Equal(t, state.SealedData, got.SealedData)
	chunks, err = api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: headLabel})
	require.NoError(t, err)
	require.Len(t, chunks.Items, 4, "one orphan and three live chunks remain")
	require.LessOrEqual(t, time.Until(c.nextGC), 10*time.Second)
	c.nextGC = time.Time{}
	got = loadTestState(t, c)
	require.Equal(t, state.SealedData, got.SealedData)
	chunks, err = api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: headLabel})
	require.NoError(t, err)
	require.Len(t, chunks.Items, 3)
	require.Greater(t, time.Until(c.nextGC), 4*time.Minute)
}

// Apply the same context-aware token bucket used by client-go REST requests.
type limitedGCClient struct {
	kubectl
	limiter flowcontrol.RateLimiter
}

func (c *limitedGCClient) listSecrets(ctx context.Context, ns string, opts metav1.ListOptions) (*corev1.SecretList, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	return c.kubectl.listSecrets(ctx, ns, opts)
}

func (c *limitedGCClient) getSecret(ctx context.Context, ns, name string) (*corev1.Secret, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	return c.kubectl.getSecret(ctx, ns, name)
}

func (c *limitedGCClient) updateSecret(ctx context.Context, ns string, secret *corev1.Secret) error {
	if err := c.limiter.Wait(ctx); err != nil {
		return err
	}
	return c.kubectl.updateSecret(ctx, ns, secret)
}

func (c *limitedGCClient) deleteSecret(ctx context.Context, ns, name string, uid types.UID) error {
	if err := c.limiter.Wait(ctx); err != nil {
		return err
	}
	return c.kubectl.deleteSecret(ctx, ns, name, uid)
}

func loadTestState(t *testing.T, c *Client) *transaction.State {
	t.Helper()
	state, err := c.GetState(t.Context())
	require.NoError(t, err)
	return state
}

type updateHookClient struct {
	kubectl
	update func(context.Context, string, *corev1.Secret) error
}

func (c *updateHookClient) updateSecret(ctx context.Context, namespace string, s *corev1.Secret) error {
	return c.update(ctx, namespace, s)
}

type createHookClient struct {
	kubectl
	create func(context.Context, string, *corev1.Secret) (*corev1.Secret, error)
}

func (c *createHookClient) createSecret(ctx context.Context, namespace string, s *corev1.Secret) (*corev1.Secret, error) {
	return c.create(ctx, namespace, s)
}

type fakeAPIClient struct {
	kubectl
	api *fake.Clientset
}

func (c *fakeAPIClient) listSecrets(ctx context.Context, namespace string, opts metav1.ListOptions) (*corev1.SecretList, error) {
	return c.api.CoreV1().Secrets(namespace).List(ctx, opts)
}

// Supply the API semantics absent from the client-go fake. Real API-server
// integration tests remain necessary for admission, limits, and authorization.
func testClient(t *testing.T) (*Client, *fake.Clientset) {
	t.Helper()
	api := fake.NewClientset()
	var mu sync.Mutex
	var version int
	api.PrependReactor("*", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		defer mu.Unlock()
		resource := schema.GroupResource{Resource: "secrets"}
		switch a.GetVerb() {
		case "create", "update":
			var s *corev1.Secret
			if a.GetVerb() == "create" {
				s = a.(k8stesting.CreateAction).GetObject().(*corev1.Secret).DeepCopy()
				s.UID = types.UID(uuid.NewString())
				s.CreationTimestamp = metav1.Now()
			} else {
				s = a.(k8stesting.UpdateAction).GetObject().(*corev1.Secret).DeepCopy()
				old, err := api.Tracker().Get(a.GetResource(), a.GetNamespace(), s.Name)
				if err != nil {
					return true, nil, err
				}
				if old.(*corev1.Secret).ResourceVersion != s.ResourceVersion || old.(*corev1.Secret).UID != s.UID {
					return true, nil, k8serrors.NewConflict(resource, s.Name, errors.New("stale reference"))
				}
			}
			version++
			s.ResourceVersion = strconv.Itoa(version)
			if a.GetVerb() == "create" {
				return true, s, api.Tracker().Create(a.GetResource(), s, a.GetNamespace())
			}
			return true, s, api.Tracker().Update(a.GetResource(), s, a.GetNamespace())
		case "delete":
			a := a.(k8stesting.DeleteAction)
			old, err := api.Tracker().Get(a.GetResource(), a.GetNamespace(), a.GetName())
			if err != nil {
				return true, nil, err
			}
			if p := a.GetDeleteOptions().Preconditions; p != nil && p.UID != nil && old.(*corev1.Secret).UID != *p.UID {
				return true, nil, k8serrors.NewConflict(resource, a.GetName(), errors.New("UID mismatch"))
			}
			return true, nil, api.Tracker().Delete(a.GetResource(), a.GetNamespace(), a.GetName())
		}
		return false, nil, nil
	})
	c := New(api, "test", "state", true, nil, zaptest.NewLogger(t))
	c.client = &fakeAPIClient{kubectl: c.client, api: api}
	// Exercise collection explicitly without wall-clock sleeps in unit tests.
	c.nextGC = time.Now().Add(time.Hour)
	return c, api
}
