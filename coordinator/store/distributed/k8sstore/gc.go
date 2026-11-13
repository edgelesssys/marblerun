/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package k8sstore

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	gcInterval      = 5 * time.Minute
	gcRetryInterval = 10 * time.Second
	// At the default 5 QPS, 64 deletes plus listing need
	// roughly 14 seconds even without other requests sharing the limiter.
	gcTimeout   = 20 * time.Second
	gcBatchSize = 64
)

var errGCIncomplete = errors.New("state chunk collection batch full")

// maybeCollect cleans up old state chunks asynchronously at most once
// every [gcInterval] on success, or every [gcRetryInterval] if
// garbage collection failed in the previous attempt.
func (c *Client) maybeCollect(ctx context.Context, head *corev1.Secret) {
	if !c.gcMu.TryLock() {
		return
	}
	if time.Now().Before(c.nextGC) {
		c.gcMu.Unlock()
		return
	}

	d, revision, err := layout(head)
	if err != nil {
		c.gcMu.Unlock()
		c.log.Warn("Collecting old state chunks failed", zap.Error(err))
		return
	}

	// Start garbage collection in a goroutine to avoid blocking request completion
	ctx = context.WithoutCancel(ctx)
	go func() {
		defer c.gcMu.Unlock()
		ctx, cancel := context.WithTimeout(ctx, gcTimeout)
		defer cancel()
		err := c.collect(ctx, revision, d)
		interval := gcInterval
		if err != nil {
			// Leave unfinished work eligible for a subsequent request soon.
			interval = gcRetryInterval
		}
		c.nextGC = time.Now().Add(interval)
		if err != nil && !errors.Is(err, errGCIncomplete) {
			c.log.Warn("Collecting old state chunks failed", zap.Error(err))
		}
	}()
}

func (c *Client) collect(ctx context.Context, revision uint64, d *descriptor) error {
	if revision < 2 {
		return nil
	}

	deleted := 0
	opts := metav1.ListOptions{LabelSelector: chunkLabel + "=true", Limit: gcBatchSize}
	for {
		page, err := c.client.listSecrets(ctx, c.namespace, opts)
		if err != nil {
			return err
		}
		for _, chunk := range page.Items {
			chunkRevision, err := strconv.ParseUint(chunk.Annotations[revisionAnnotation], 10, 64)
			if err != nil || chunkRevision >= revision-1 || !ownsChunk(c.namespace, &chunk) || currentChunk(&chunk, d) {
				continue
			}
			if err := c.client.deleteSecret(ctx, c.namespace, chunk.Name, chunk.UID); err != nil && !k8serrors.IsNotFound(err) {
				return err
			}
			deleted++
			if deleted == gcBatchSize {
				return errGCIncomplete
			}
		}
		if page.Continue == "" {
			return nil
		}
		opts.Continue = page.Continue
	}
}

func currentChunk(chunk *corev1.Secret, d *descriptor) bool {
	return d != nil && slices.Contains(d.Chunks, chunk.Name)
}
