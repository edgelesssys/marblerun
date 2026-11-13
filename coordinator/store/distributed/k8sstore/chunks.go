/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package k8sstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/edgelesssys/marblerun/coordinator/store/distributed/transaction"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	descriptorKey      = "state-chunks.json"
	revisionAnnotation = "marblerun.edgeless.systems/state-revision"
	headLabel          = "marblerun.edgeless.systems/state-head"
	revisionLabel      = "marblerun.edgeless.systems/state-revision"
	uploadLabel        = "marblerun.edgeless.systems/state-upload"
	indexLabel         = "marblerun.edgeless.systems/state-index"
	chunkSize          = 512 * 1024
	// Bound allocations and API requests when interpreting untrusted storage.
	maxStateSize = 16 * 1024 * 1024
)

type descriptor struct {
	Version  int    `json:"version"`
	Revision uint64 `json:"revision"`
	Upload   string `json:"upload"`
	Count    int    `json:"count"`
	Size     int    `json:"size"`
	Digest   string `json:"sha256"`
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
	raw, chunked := head.Data[descriptorKey]
	if !chunked {
		return nil, revision, nil
	}
	var d descriptor
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, 0, fmt.Errorf("invalid chunk descriptor: %w", err)
	}
	_, inline := head.Data[stdstore.SealedDataFname]
	_, key := head.Data[stdstore.SealedKeyFname]
	upload, err := uuid.Parse(d.Upload)
	digest, digestErr := hex.DecodeString(d.Digest)
	if inline || !key || head.UID == "" || d.Version != 1 || d.Revision == 0 || d.Revision != revision ||
		err != nil || upload.String() != d.Upload || digestErr != nil || len(digest) != sha256.Size ||
		d.Size <= 0 || d.Size > maxStateSize || d.Count != (d.Size+chunkSize-1)/chunkSize {
		return nil, 0, errors.New("invalid or unsupported chunked state layout")
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

func chunkName(head *corev1.Secret, d *descriptor, index int) string {
	return fmt.Sprintf("mr-state-%s-%d-%s-%d", head.UID, d.Revision, d.Upload, index)
}

func ownsChunk(head, chunk *corev1.Secret) bool {
	if chunk.Labels[headLabel] != string(head.UID) || chunk.Namespace != head.Namespace {
		return false
	}
	for _, owner := range chunk.OwnerReferences {
		if owner.APIVersion == "v1" && owner.Kind == "Secret" && owner.Name == head.Name && owner.UID == head.UID {
			return true
		}
	}
	return false
}

func (c *Client) writeChunks(ctx context.Context, head *corev1.Secret, revision uint64, data []byte) error {
	if head.UID == "" || head.ResourceVersion == "" {
		return errors.New("chunking requires a persisted state reference")
	}
	if len(data) == 0 || len(data) > maxStateSize {
		return fmt.Errorf("sealed state size must be between 1 and %d bytes", maxStateSize)
	}
	upload, err := uuid.NewRandom()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	d := descriptor{Version: 1, Revision: revision, Upload: upload.String(), Count: (len(data) + chunkSize - 1) / chunkSize, Size: len(data), Digest: hex.EncodeToString(digest[:])}
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	delete(head.Data, stdstore.SealedDataFname)
	head.Data[descriptorKey] = raw
	if secretDataSize(head) > corev1.MaxSecretSize {
		return errors.New("state descriptor and wrapped key exceed the Kubernetes Secret limit")
	}
	immutable := true
	for i := range d.Count {
		chunk := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: chunkName(head, &d, i), Namespace: head.Namespace,
				Labels:          map[string]string{headLabel: string(head.UID), revisionLabel: strconv.FormatUint(revision, 10), uploadLabel: d.Upload, indexLabel: strconv.Itoa(i)},
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Secret", Name: head.Name, UID: head.UID}},
			},
			Immutable: &immutable,
			Data:      map[string][]byte{"chunk": data[i*chunkSize : min((i+1)*chunkSize, len(data))]},
		}
		if _, err := c.client.createSecret(ctx, c.namespace, chunk); err != nil {
			return fmt.Errorf("creating state chunk %d: %w", i, err)
		}
	}
	return nil
}

func (c *Client) readState(ctx context.Context, head *corev1.Secret) (*transaction.State, error) {
	for range 3 {
		d, revision, err := layout(head)
		if err != nil {
			return nil, err
		}
		data := head.Data[stdstore.SealedDataFname]
		if d != nil {
			data, err = c.readChunks(ctx, head, d)
			if k8serrors.IsNotFound(err) {
				latest, getErr := c.client.getSecret(ctx, c.namespace, c.secretName)
				if getErr != nil {
					return nil, getErr
				}
				if latest.UID != head.UID {
					return nil, errors.New("state head replaced during read")
				}
				if string(latest.Data[descriptorKey]) != string(head.Data[descriptorKey]) {
					head = latest
					continue
				}
			}
			if err != nil {
				return nil, fmt.Errorf("reading committed state chunks: %w", err)
			}
		}
		c.observeState(revision, len(data)+len(head.Data[stdstore.SealedKeyFname]))
		return &transaction.State{SealedData: data, SealedKey: head.Data[stdstore.SealedKeyFname], StateRef: head}, nil
	}
	return nil, errors.New("state changed repeatedly during chunk read: retry operation")
}

func (c *Client) readChunks(ctx context.Context, head *corev1.Secret, d *descriptor) ([]byte, error) {
	data := make([]byte, 0, d.Size)
	for i := range d.Count {
		chunk, err := c.client.getSecret(ctx, c.namespace, chunkName(head, d, i))
		if err != nil {
			return nil, err
		}
		if !ownsChunk(head, chunk) || chunk.Immutable == nil || !*chunk.Immutable ||
			chunk.Labels[revisionLabel] != strconv.FormatUint(d.Revision, 10) || chunk.Labels[uploadLabel] != d.Upload ||
			chunk.Labels[indexLabel] != strconv.Itoa(i) || len(chunk.Data["chunk"]) != min(chunkSize, d.Size-i*chunkSize) {
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
