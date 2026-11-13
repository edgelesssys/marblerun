/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package k8sstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/edgelesssys/marblerun/coordinator/store/distributed/transaction"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	descriptorKey      = "state-chunks.json"
	chunkedTombstone   = "chunked"
	revisionAnnotation = "marblerun.edgeless.systems/state-revision"
	chunkLabel         = "marblerun.edgeless.systems/state-chunk"
	chunkPrefix        = "marblerun-state-"
	chunkSize          = 512 * 1024
	// Bound allocations and API requests when interpreting untrusted storage.
	maxStateSize = 16 * 1024 * 1024
)

type descriptor struct {
	Version  int      `json:"version"`
	Revision uint64   `json:"revision"`
	Chunks   []string `json:"chunks"`
	Size     int      `json:"size"`
	Digest   string   `json:"sha256"`
}

func layout(head *corev1.Secret) (*descriptor, uint64, error) {
	var revision uint64
	if raw, ok := head.Annotations[revisionAnnotation]; ok {
		var err error
		revision, err = strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid state revision: %w", err)
		}
	}
	raw, hasDescriptor := head.Data[descriptorKey]
	chunked := string(head.Data[stdstore.SealedDataFname]) == chunkedTombstone
	if chunked != hasDescriptor {
		return nil, 0, errors.New("inconsistent state detected: chunked state should have both a sealed data tombstone and a chunk descriptor")
	}
	if !chunked {
		return nil, revision, nil
	}
	var d descriptor
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, 0, fmt.Errorf("invalid chunk descriptor: %w", err)
	}
	_, key := head.Data[stdstore.SealedKeyFname]
	digest, digestErr := hex.DecodeString(d.Digest)
	if !key || head.UID == "" || d.Version != 2 || d.Revision == 0 || d.Revision != revision ||
		digestErr != nil || len(digest) != sha256.Size ||
		d.Size <= 0 || d.Size > maxStateSize || len(d.Chunks) != (d.Size+chunkSize-1)/chunkSize {
		return nil, 0, errors.New("invalid or unsupported chunked state layout")
	}
	seen := make(map[string]bool, len(d.Chunks))
	for _, name := range d.Chunks {
		if !validChunkName(name) || seen[name] {
			return nil, 0, errors.New("invalid or duplicate state chunk name")
		}
		seen[name] = true
	}
	return &d, revision, nil
}

func secretDataSize(secret *corev1.Secret) int {
	var size int
	for _, value := range secret.Data {
		size += len(value)
	}
	return size
}

func validChunkName(name string) bool {
	id, err := uuid.Parse(strings.TrimPrefix(name, chunkPrefix))
	return err == nil && name == chunkPrefix+id.String()
}

func ownsChunk(namespace string, chunk *corev1.Secret) bool {
	return chunk.Namespace == namespace && chunk.Labels[chunkLabel] == "true" && validChunkName(chunk.Name)
}

func validChunkMetadata(head, chunk *corev1.Secret, revision uint64) bool {
	return ownsChunk(head.Namespace, chunk) && chunk.Immutable != nil && *chunk.Immutable &&
		chunk.Annotations[revisionAnnotation] == strconv.FormatUint(revision, 10)
}

func (c *Client) writeChunks(ctx context.Context, head *corev1.Secret, revision uint64, data []byte) error {
	if head.UID == "" || head.ResourceVersion == "" {
		return errors.New("chunking requires a persisted state reference")
	}
	if len(data) == 0 || len(data) > maxStateSize {
		return fmt.Errorf("sealed state size must be between 1 and %d bytes", maxStateSize)
	}
	digest := sha256.Sum256(data)
	d := descriptor{Version: 2, Revision: revision, Size: len(data), Digest: hex.EncodeToString(digest[:])}
	for range (len(data) + chunkSize - 1) / chunkSize {
		id, err := uuid.NewRandom()
		if err != nil {
			return err
		}
		d.Chunks = append(d.Chunks, chunkPrefix+id.String())
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}

	// Add a tombstone in place of the old sealed data to prevent
	// older Coordinator instances from interpreting the chunk head
	// as uninitialized state.
	head.Data[stdstore.SealedDataFname] = []byte(chunkedTombstone)
	head.Data[descriptorKey] = raw
	if secretDataSize(head) > corev1.MaxSecretSize {
		return errors.New("state descriptor and wrapped key exceed the Kubernetes Secret limit")
	}
	immutable := true
	for i, name := range d.Chunks {
		chunk := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: head.Namespace,
				Labels:      map[string]string{chunkLabel: "true"},
				Annotations: map[string]string{revisionAnnotation: strconv.FormatUint(revision, 10)},
			},
			Immutable: &immutable,
			Data:      map[string][]byte{"chunk": data[i*chunkSize : min((i+1)*chunkSize, len(data))]},
		}
		created, err := c.client.createSecret(ctx, c.namespace, chunk)
		if err != nil {
			return fmt.Errorf("creating state chunk %d: %w", i, err)
		}

		// Check that our chunk wasn't modified by a mutating webhook
		if created.Name != name || !validChunkMetadata(head, created, revision) ||
			len(created.OwnerReferences) != 0 ||
			!bytes.Equal(created.Data["chunk"], data[i*chunkSize:min((i+1)*chunkSize, len(data))]) {
			return fmt.Errorf("created state chunk %d differs from the required layout or ciphertext: check mutating admission policies", i)
		}
	}
	return nil
}

func (c *Client) readState(ctx context.Context, head *corev1.Secret) (*transaction.State, error) {
	d, _, err := layout(head)
	if err != nil {
		return nil, err
	}
	data := head.Data[stdstore.SealedDataFname]
	if d != nil {
		data, err = c.readChunks(ctx, head, d)
		if err != nil {
			return nil, fmt.Errorf("reading committed state chunks: %w", err)
		}
	}
	return &transaction.State{SealedData: data, SealedKey: head.Data[stdstore.SealedKeyFname], StateRef: head}, nil
}

func (c *Client) readChunks(ctx context.Context, head *corev1.Secret, d *descriptor) ([]byte, error) {
	data := make([]byte, 0, d.Size)
	for i, name := range d.Chunks {
		chunk, err := c.client.getSecret(ctx, c.namespace, name)
		if err != nil {
			return nil, err
		}
		if !validChunkMetadata(head, chunk, d.Revision) || len(chunk.Data["chunk"]) != min(chunkSize, d.Size-i*chunkSize) {
			return nil, fmt.Errorf("invalid state chunk %d", i)
		}
		data = append(data, chunk.Data["chunk"]...)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != d.Digest {
		return nil, errors.New("state chunk digest mismatch")
	}
	return data, nil
}
