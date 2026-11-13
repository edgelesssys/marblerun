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
	"sync/atomic"
	"testing"
	"time"

	"github.com/edgelesssys/marblerun/coordinator/seal"
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
			waitForGC(cl)
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
		wantErr string
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
			wantErr: "failed",
		},
		"invalid state ref": {
			kubectl: &stubKubeClient{
				secret: &corev1.Secret{},
			},
			state:   &transaction.State{StateRef: map[string]byte{}},
			wantErr: "invalid state reference",
		},
		"revision overflow": {
			kubectl: &stubKubeClient{},
			state: &transaction.State{StateRef: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{revisionAnnotation: strconv.FormatUint(^uint64(0), 10)}},
			}},
			wantErr: "overflow",
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
			waitForGC(cl)
			if tc.wantErr != "" {
				assert.ErrorContains(err, tc.wantErr)
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
	legacy, err := api.CoreV1().Secrets(c.namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: c.secretName, Namespace: c.namespace},
		Data: map[string][]byte{
			stdstore.SealedDataFname: []byte("legacy sealed state"),
			stdstore.SealedKeyFname:  []byte("legacy wrapped key"),
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	state, err := c.GetState(ctx)
	require.NoError(t, err)
	require.Equal(t, legacy.Data[stdstore.SealedDataFname], state.SealedData)
	require.Equal(t, legacy.Data[stdstore.SealedKeyFname], state.SealedKey)
	require.Equal(t, legacy, state.StateRef, "reading legacy state must not rewrite it")
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
	require.NoError(t, c.SaveState(ctx, state))
	// Save must not mutate the reference used by the caller's transaction.
	require.NotContains(t, inline.Data, descriptorKey)
	loaded, err := c.GetState(ctx)
	require.NoError(t, err)
	require.Equal(t, state.SealedData, loaded.SealedData)
	require.Equal(t, state.SealedKey, loaded.SealedKey)
	require.Equal(t, "2", loaded.StateRef.(*corev1.Secret).Annotations[revisionAnnotation])
	// Old readers read sealed_data directly. It must be nonempty and fail
	// unsealing, even with an encryption key already cached.
	tombstone := loaded.StateRef.(*corev1.Secret).Data[stdstore.SealedDataFname]
	require.Equal(t, []byte("chunked"), tombstone)
	for _, sealer := range []seal.Sealer{seal.NewAESGCMSealer(zaptest.NewLogger(t)), seal.NewNoEnclaveSealer(zaptest.NewLogger(t))} {
		_, plaintext, err := sealer.UnsealWithKey(tombstone, bytes.Repeat([]byte{0x42}, 32))
		require.Error(t, err)
		require.Nil(t, plaintext)
	}
	// A writer that loaded the inline state before migration cannot publish it.
	stale := inline.DeepCopy()
	stale.Data[stdstore.SealedDataFname] = []byte("stale legacy write")
	_, err = api.CoreV1().Secrets(c.namespace).Update(ctx, stale, metav1.UpdateOptions{})
	require.True(t, k8serrors.IsConflict(err))
	// Shrinking never goes inline.
	loaded.SealedData = []byte("small state after migration")
	require.NoError(t, c.SaveState(ctx, loaded))
	got, err := c.GetState(ctx)
	require.NoError(t, err)
	require.Equal(t, loaded.SealedData, got.SealedData)
	require.Contains(t, got.StateRef.(*corev1.Secret).Data, descriptorKey)
	require.Equal(t, []byte("chunked"), got.StateRef.(*corev1.Secret).Data[stdstore.SealedDataFname])
	require.Equal(t, "3", got.StateRef.(*corev1.Secret).Annotations[revisionAnnotation])
	all, err := api.CoreV1().Secrets(c.namespace).List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	for _, item := range all.Items {
		require.LessOrEqual(t, secretDataSize(&item), corev1.MaxSecretSize)
	}
}

func TestChunkedBackupRestore(t *testing.T) {
	c, api := testClient(t)
	data := append(bytes.Repeat([]byte{0x31}, chunkSize), bytes.Repeat([]byte{0x72}, chunkSize+13)...)
	backup := commitTestState(t, c, data, []byte("backup key"))
	backupHead := backup.StateRef.(*corev1.Secret)
	// Offline restore recreates the same snapshot in a fresh namespace with new UIDs.
	objects, err := api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{})
	require.NoError(t, err)
	restored, target := testClient(t)
	restored.namespace = "restored"
	for _, object := range objects.Items {
		if object.Name != c.secretName {
			require.Regexp(t, `^marblerun-state-[0-9a-f-]{36}$`, object.Name)
			require.Empty(t, object.OwnerReferences, "restored chunks must not depend on old Kubernetes owners")
		}
		oldUID := object.UID
		object.ObjectMeta = metav1.ObjectMeta{
			Name: object.Name, Namespace: restored.namespace,
			Labels: object.Labels, Annotations: object.Annotations,
		}
		created, err := target.CoreV1().Secrets(restored.namespace).Create(t.Context(), &object, metav1.CreateOptions{})
		require.NoError(t, err)
		require.NotEqual(t, oldUID, created.UID)
	}
	got := loadTestState(t, restored)
	require.Equal(t, backup.SealedData, got.SealedData)
	require.Equal(t, backup.SealedKey, got.SealedKey)
	require.Equal(t, backupHead.Data[descriptorKey], got.StateRef.(*corev1.Secret).Data[descriptorKey])
	// Restore needs no rewriting of names, descriptors or identity labels.
	got.SealedData, got.SealedKey = []byte("new state after restore"), []byte("new key")
	require.NoError(t, restored.SaveState(t.Context(), got))
	current := loadTestState(t, restored)
	require.Equal(t, got.SealedData, current.SealedData)
	require.Equal(t, got.SealedKey, current.SealedKey)
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
			state := commitTestState(t, c, []byte("previous"), []byte("old-key"))
			state.SealedData = bytes.Repeat([]byte("new"), corev1.MaxSecretSize/3+12)
			state.SealedKey = []byte("new-key")
			if failure == "upload" {
				created := 0
				api.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
					created++
					if created == 2 {
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

func TestChunkAdmission(t *testing.T) {
	testCases := map[string]struct {
		mutate  func(chunk, head *corev1.Secret)
		wantErr bool
	}{
		"label":             {mutate: func(s, _ *corev1.Secret) { delete(s.Labels, chunkLabel) }, wantErr: true},
		"revision":          {mutate: func(s, _ *corev1.Secret) { s.Annotations[revisionAnnotation] = "0" }, wantErr: true},
		"mutable":           {mutate: func(s, _ *corev1.Secret) { *s.Immutable = false }, wantErr: true},
		"missing immutable": {mutate: func(s, _ *corev1.Secret) { s.Immutable = nil }, wantErr: true},
		"ciphertext":        {mutate: func(s, _ *corev1.Secret) { s.Data["chunk"][0] ^= 0xff }, wantErr: true},
		"owner": {
			mutate: func(s, head *corev1.Secret) {
				s.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Secret", Name: head.Name, UID: head.UID}}
			},
			wantErr: true,
		},
		"unrelated metadata": {mutate: func(s, _ *corev1.Secret) { s.Annotations["example.com/policy"] = "allowed" }},
	}
	for _, chunked := range []bool{false, true} {
		for name, tc := range testCases {
			t.Run(fmt.Sprintf("chunked=%t/%s", chunked, name), func(t *testing.T) {
				c, _ := testClient(t)
				data := []byte("previous")
				if chunked {
					data = bytes.Repeat([]byte{0x31}, corev1.MaxSecretSize+1)
				}
				previous := commitTestState(t, c, data, []byte("previous key"))
				state := loadTestState(t, c)
				state.SealedData, state.SealedKey = bytes.Repeat([]byte{0x72}, corev1.MaxSecretSize+13), []byte("new key")
				backend := c.client
				created := 0
				c.client = &createHookClient{kubectl: backend, create: func(ctx context.Context, namespace string, s *corev1.Secret) (*corev1.Secret, error) {
					s = s.DeepCopy()
					// Mutate a later chunk to cover partially completed uploads.
					created++
					if created == 2 {
						tc.mutate(s, previous.StateRef.(*corev1.Secret))
					}
					return backend.createSecret(ctx, namespace, s)
				}}
				err := c.SaveState(t.Context(), state)
				got := loadTestState(t, c)
				if tc.wantErr {
					require.ErrorContains(t, err, "check mutating admission policies")
					require.Equal(t, previous, got, "failed upload must preserve the complete committed state and head")
				} else {
					require.NoError(t, err)
					require.Equal(t, state.SealedData, got.SealedData)
					require.Equal(t, state.SealedKey, got.SealedKey)
				}
			})
		}
	}
}

func TestChunkIntegrity(t *testing.T) {
	// Different contents in equal-sized chunks make reordering detectable by the digest.
	data := append(bytes.Repeat([]byte{0x31}, chunkSize), bytes.Repeat([]byte{0x72}, chunkSize+13)...)
	resource := corev1.SchemeGroupVersion.WithResource("secrets")
	for name, tc := range map[string]struct {
		mutate  func(*descriptor)
		wantErr string
	}{
		"version":   {mutate: func(d *descriptor) { d.Version = 1 }},
		"size":      {mutate: func(d *descriptor) { d.Size = maxStateSize + 1 }},
		"names":     {mutate: func(d *descriptor) { d.Chunks[0] = "unrelated-secret" }},
		"duplicate": {mutate: func(d *descriptor) { d.Chunks[1] = d.Chunks[0] }},
		"order":     {mutate: func(d *descriptor) { d.Chunks[0], d.Chunks[1] = d.Chunks[1], d.Chunks[0] }, wantErr: "digest mismatch"},
		"count":     {mutate: func(d *descriptor) { d.Chunks = d.Chunks[:1] }},
	} {
		t.Run("descriptor/"+name, func(t *testing.T) {
			c, api := testClient(t)
			head := commitTestState(t, c, data, nil).StateRef.(*corev1.Secret)
			var d descriptor
			require.NoError(t, json.Unmarshal(head.Data[descriptorKey], &d))
			tc.mutate(&d)
			raw, err := json.Marshal(d)
			require.NoError(t, err)
			head.Data[descriptorKey] = raw
			require.NoError(t, api.Tracker().Update(resource, head, c.namespace))
			_, err = c.GetState(t.Context())
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
	for name, mutate := range map[string]func(*corev1.Secret){
		"mixed layout":       func(s *corev1.Secret) { s.Data[stdstore.SealedDataFname] = []byte("inline") },
		"missing tombstone":  func(s *corev1.Secret) { delete(s.Data, stdstore.SealedDataFname) },
		"empty tombstone":    func(s *corev1.Secret) { s.Data[stdstore.SealedDataFname] = []byte{} },
		"missing descriptor": func(s *corev1.Secret) { delete(s.Data, descriptorKey) },
		"revision":           func(s *corev1.Secret) { s.Annotations[revisionAnnotation] = "broken" },
	} {
		t.Run("head/"+name, func(t *testing.T) {
			c, api := testClient(t)
			head := commitTestState(t, c, data, nil).StateRef.(*corev1.Secret)
			mutate(head)
			require.NoError(t, api.Tracker().Update(resource, head, c.namespace))
			_, err := c.GetState(t.Context())
			require.Error(t, err)
		})
	}
	for name, tc := range map[string]struct {
		mutate func(*corev1.Secret)
		remove bool
	}{
		"missing":  {remove: true},
		"digest":   {mutate: func(s *corev1.Secret) { s.Data["chunk"][0] ^= 0xff }},
		"label":    {mutate: func(s *corev1.Secret) { delete(s.Labels, chunkLabel) }},
		"revision": {mutate: func(s *corev1.Secret) { s.Annotations[revisionAnnotation] = "0" }},
	} {
		t.Run("chunk/"+name, func(t *testing.T) {
			c, api := testClient(t)
			head := commitTestState(t, c, data, nil).StateRef.(*corev1.Secret)
			var d descriptor
			require.NoError(t, json.Unmarshal(head.Data[descriptorKey], &d))
			if tc.remove {
				require.NoError(t, api.Tracker().Delete(resource, c.namespace, d.Chunks[1]))
			} else {
				chunk, err := api.CoreV1().Secrets(c.namespace).Get(t.Context(), d.Chunks[0], metav1.GetOptions{})
				require.NoError(t, err)
				tc.mutate(chunk)
				require.NoError(t, api.Tracker().Update(resource, chunk, c.namespace))
			}
			got, err := c.GetState(t.Context())
			require.Error(t, err)
			require.Nil(t, got, "never return partial or invalid state")
			if tc.remove {
				require.True(t, k8serrors.IsNotFound(err))
			}
		})
	}
}

func TestGarbageCollection(t *testing.T) {
	for name, data := range map[string][]byte{
		"inline":  []byte("inline state"),
		"chunked": bytes.Repeat([]byte{0x71}, corev1.MaxSecretSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			c, api := testClient(t)
			state := loadTestState(t, c)
			orphan, err := api.CoreV1().Secrets(c.namespace).Create(t.Context(), &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: chunkPrefix + uuid.NewString(), Namespace: c.namespace,
					Labels: map[string]string{chunkLabel: "true"}, Annotations: map[string]string{revisionAnnotation: "1"},
				},
			}, metav1.CreateOptions{})
			require.NoError(t, err)
			state.SealedData, state.SealedKey = data, []byte("previous key")
			for revision := 0; revision <= 2; revision++ {
				collectTestState(t, c, state.StateRef.(*corev1.Secret))
				_, err := api.CoreV1().Secrets(c.namespace).Get(t.Context(), orphan.Name, metav1.GetOptions{})
				require.NoError(t, err, "initial revisions must retain current, future and previous uploads")
				if revision < 2 {
					require.NoError(t, c.SaveState(t.Context(), state))
					state = loadTestState(t, c)
				}
			}
			previous := state
			current := commitTestState(t, c, []byte("current state"), []byte("current key"))
			head := current.StateRef.(*corev1.Secret)
			require.Equal(t, "3", head.Annotations[revisionAnnotation])
			for name, tc := range map[string]struct {
				revision       string
				alreadyDeleted bool
				wantDeleted    bool
			}{
				"old":             {revision: "1", wantDeleted: true},
				"already deleted": {revision: "1", alreadyDeleted: true, wantDeleted: true},
				"previous":        {revision: "2"},
				"current":         {revision: "3"},
				"next upload":     {revision: "4"},
				"future":          {revision: "10"},
				"missing":         {},
				"invalid":         {revision: "invalid"},
				"overflow":        {revision: "18446744073709551616"},
			} {
				t.Run(name, func(t *testing.T) {
					chunk := orphan.DeepCopy()
					chunk.Name = chunkPrefix + uuid.NewString()
					chunk.Annotations[revisionAnnotation] = tc.revision
					if tc.revision == "" {
						delete(chunk.Annotations, revisionAnnotation)
					}
					// Even newly created old revisions are eligible; no age threshold remains.
					_, err := api.CoreV1().Secrets(c.namespace).Create(t.Context(), chunk, metav1.CreateOptions{})
					require.NoError(t, err)
					if tc.alreadyDeleted {
						reactors := api.ReactionChain
						t.Cleanup(func() { api.ReactionChain = reactors })
						api.PrependReactor("delete", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
							// Simulate another collector deleting this candidate after our list.
							if a.(k8stesting.DeleteAction).GetName() == chunk.Name {
								require.NoError(t, api.Tracker().Delete(a.GetResource(), c.namespace, chunk.Name))
							}
							return false, nil, nil
						})
					}
					collectTestState(t, c, head)
					_, err = api.CoreV1().Secrets(c.namespace).Get(t.Context(), chunk.Name, metav1.GetOptions{})
					if tc.wantDeleted {
						require.True(t, k8serrors.IsNotFound(err))
					} else {
						require.NoError(t, err)
					}
				})
			}
			require.Equal(t, current, loadTestState(t, c), "GC must preserve the current data, key and head")
			got, err := c.readState(t.Context(), previous.StateRef.(*corev1.Secret))
			require.NoError(t, err)
			require.Equal(t, previous, got, "the previous snapshot must remain readable")
		})
	}
}

func TestBackgroundCollection(t *testing.T) {
	for _, trigger := range []string{"read", "write"} {
		t.Run(trigger, func(t *testing.T) {
			c, api := testClient(t)
			stale := loadTestState(t, c)
			commitTestState(t, c, bytes.Repeat([]byte{0x71}, corev1.MaxSecretSize+1), nil)
			commitTestState(t, c, []byte("previous snapshot"), nil)
			state := commitTestState(t, c, []byte("current snapshot"), nil)
			base := c.client
			started, release := make(chan struct{}, 1), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(func() { unblock(); waitForGC(c) })
			var lists atomic.Int32
			c.client = &listHookClient{kubectl: base, list: func(ctx context.Context, ns string, opts metav1.ListOptions) (*corev1.SecretList, error) {
				lists.Add(1)
				select {
				case started <- struct{}{}:
				default:
				}
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return base.listSecrets(ctx, ns, opts)
			}}
			c.nextGC = time.Time{}
			// A failed publication must not trigger background work.
			require.Error(t, c.SaveState(t.Context(), stale))
			waitForGC(c)
			require.Zero(t, lists.Load())
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if trigger == "write" {
					done <- c.SaveState(ctx, state)
				} else {
					_, err := c.GetState(ctx)
					done <- err
				}
			}()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("request blocked on background collection")
			}
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("request did not trigger collection")
			}
			cancel() // Request completion must not cancel the collector.
			var readers sync.WaitGroup
			for range 2 {
				readers.Go(func() {
					got, err := c.GetState(t.Context())
					if assert.NoError(t, err) {
						assert.Equal(t, []byte("current snapshot"), got.SealedData)
					}
				})
			}
			readers.Wait()
			unblock()
			waitForGC(c)
			require.EqualValues(t, 1, lists.Load(), "concurrent triggers must not queue collectors")
			chunks, err := api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: chunkLabel})
			require.NoError(t, err)
			require.Len(t, chunks.Items, 2, "only current and previous snapshots survive")
			require.Equal(t, state.SealedData, loadTestState(t, c).SealedData)
			waitForGC(c)
			require.EqualValues(t, 1, lists.Load(), "reads must respect the time throttle")
		})
	}
}

type listHookClient struct {
	kubectl
	list func(context.Context, string, metav1.ListOptions) (*corev1.SecretList, error)
}

func (c *listHookClient) listSecrets(ctx context.Context, ns string, opts metav1.ListOptions) (*corev1.SecretList, error) {
	return c.list(ctx, ns, opts)
}

func TestCollectionResumesFullBatch(t *testing.T) {
	c, api := testClient(t)
	commitTestState(t, c, []byte("inline"), nil)
	commitTestState(t, c, []byte("inline"), nil)
	state := commitTestState(t, c, bytes.Repeat([]byte{1}, corev1.MaxSecretSize+1), nil)
	chunks, err := api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: chunkLabel})
	require.NoError(t, err)
	for range gcBatchSize + 8 {
		chunk := chunks.Items[0].DeepCopy()
		chunk.Name = chunkPrefix + uuid.NewString()
		chunk.Annotations[revisionAnnotation] = "1"
		require.NoError(t, api.Tracker().Create(corev1.SchemeGroupVersion.WithResource("secrets"), chunk, c.namespace))
	}
	limiter := flowcontrol.NewTokenBucketRateLimiter(rest.DefaultQPS, rest.DefaultBurst)
	defer limiter.Stop()
	c.client = &limitedGCClient{kubectl: c.client, limiter: limiter}
	// Exhaust the default 5 QPS / burst 10 bucket, as after a state upload.
	for limiter.TryAccept() {
	}
	d, revision, err := layout(state.StateRef.(*corev1.Secret))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	require.Error(t, c.collect(ctx, revision, d))
	cancel()
	chunks, err = api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: chunkLabel})
	require.NoError(t, err)
	remaining := len(chunks.Items)
	require.Greater(t, remaining, gcBatchSize+3)
	require.Less(t, remaining, gcBatchSize+8+3, "deadline must interrupt after partial progress")
	c.nextGC = time.Time{}
	got := loadTestState(t, c)
	waitForGC(c)
	require.Equal(t, state.SealedData, got.SealedData)
	chunks, err = api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: chunkLabel})
	require.NoError(t, err)
	require.Len(t, chunks.Items, remaining-gcBatchSize, "a full batch must fit within the production timeout")
	require.LessOrEqual(t, time.Until(waitForGC(c)), 10*time.Second)
	c.nextGC = time.Time{}
	got = loadTestState(t, c)
	waitForGC(c)
	require.Equal(t, state.SealedData, got.SealedData)
	chunks, err = api.CoreV1().Secrets(c.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: chunkLabel})
	require.NoError(t, err)
	require.Len(t, chunks.Items, 3)
	require.Greater(t, time.Until(waitForGC(c)), 4*time.Minute)
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

func (c *limitedGCClient) deleteSecret(ctx context.Context, ns, name string, uid types.UID) error {
	if err := c.limiter.Wait(ctx); err != nil {
		return err
	}
	return c.kubectl.deleteSecret(ctx, ns, name, uid)
}

// waitForGC joins any active pass and returns its next eligible collection time.
func waitForGC(c *Client) time.Time {
	c.gcMu.Lock()
	defer c.gcMu.Unlock()
	return c.nextGC
}

func loadTestState(t *testing.T, c *Client) *transaction.State {
	t.Helper()
	state, err := c.GetState(t.Context())
	require.NoError(t, err)
	return state
}

// commitTestState prepares a committed fixture, returning a fresh reference.
func commitTestState(t *testing.T, c *Client, data, key []byte) *transaction.State {
	t.Helper()
	state := loadTestState(t, c)
	state.SealedData, state.SealedKey = data, key
	require.NoError(t, c.SaveState(t.Context(), state))
	return loadTestState(t, c)
}

func collectTestState(t *testing.T, c *Client, head *corev1.Secret) {
	t.Helper()
	d, revision, err := layout(head)
	require.NoError(t, err)
	require.NoError(t, c.collect(t.Context(), revision, d))
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
	c := New(api, "test", "state", zaptest.NewLogger(t))
	c.client = &fakeAPIClient{kubectl: c.client, api: api}
	// Exercise collection explicitly without wall-clock sleeps in unit tests.
	c.nextGC = time.Now().Add(time.Hour)
	t.Cleanup(func() { waitForGC(c) })
	return c, api
}
