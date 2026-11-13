/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package k8sstore

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	gcBarrierAnnotation = "marblerun.edgeless.systems/gc-barrier"
	gcInterval          = 5 * time.Minute
	gcRetryInterval     = 10 * time.Second
	gcRetention         = 10 * time.Minute
	// At the default 5 QPS, 64 deletes plus listing and the barrier need
	// roughly 14 seconds even without other requests sharing the limiter.
	gcTimeout   = 20 * time.Second
	gcBatchSize = 64
)

var errGCIncomplete = errors.New("state chunk collection batch full")

// maybeCollect is synchronous and bounded: it owns no goroutine, and errors never
// change the outcome of a successful commit. The return value tells readers to
// refresh their head, since a barrier may have changed its resourceVersion.
func (c *Client) maybeCollect(ctx context.Context, head *corev1.Secret) bool {
	if !c.gcMu.TryLock() {
		return false
	}
	defer c.gcMu.Unlock()
	if time.Now().Before(c.nextGC) {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, gcTimeout)
	defer cancel()
	start := time.Now()
	err := c.collect(ctx, head, start.Add(-gcRetention))
	interval := gcInterval
	if err != nil {
		// A full batch or failed pass may leave eligible chunks behind. Do
		// not postpone remaining work for another normal collection interval.
		interval = gcRetryInterval
	}
	c.nextGC = time.Now().Add(interval)
	if c.metrics.gcDuration != nil {
		c.metrics.gcDuration.Observe(time.Since(start).Seconds())
	}
	if err != nil && !errors.Is(err, errGCIncomplete) {
		if c.metrics.gcErrors != nil {
			c.metrics.gcErrors.Inc()
		}
		c.log.Warn("Collecting old state chunks failed", zap.Error(err))
	}
	return true
}

func (c *Client) collect(ctx context.Context, head *corev1.Secret, cutoff time.Time) error {
	d, _, err := layout(head)
	if err != nil {
		return err
	}
	// Finish selecting a bounded batch BEFORE the barrier. In particular, never
	// continue pagination after the barrier, which could include new writers.
	var candidates []corev1.Secret
	opts := metav1.ListOptions{LabelSelector: headLabel + "=" + string(head.UID), Limit: 128}
	for {
		page, err := c.client.listSecrets(ctx, c.namespace, opts)
		if err != nil {
			return err
		}
		for _, chunk := range page.Items {
			if ownsChunk(head, &chunk) && chunk.CreationTimestamp.Time.Before(cutoff) && !currentChunk(&chunk, d) {
				// Retain only metadata, not potentially large ciphertext buffers.
				chunk.Data = nil
				candidates = append(candidates, chunk)
				if len(candidates) == gcBatchSize {
					break
				}
			}
		}
		if len(candidates) == gcBatchSize || page.Continue == "" {
			break
		}
		opts.Continue = page.Continue
	}
	if c.metrics.gcCandidates != nil {
		c.metrics.gcCandidates.Set(float64(len(candidates)))
	}
	if len(candidates) == 0 {
		return nil
	}
	for range 3 {
		current, err := c.client.getSecret(ctx, c.namespace, c.secretName)
		if err != nil {
			return err
		}
		if current.UID != head.UID {
			return errors.New("state head replaced during collection")
		}
		d, _, err = layout(current)
		if err != nil {
			return err
		}
		barrier, err := uuid.NewRandom()
		if err != nil {
			return err
		}
		current = current.DeepCopy()
		if current.Annotations == nil {
			current.Annotations = map[string]string{}
		}
		current.Annotations[gcBarrierAnnotation] = barrier.String()
		if err := c.client.updateSecret(ctx, c.namespace, current); err != nil {
			if k8serrors.IsConflict(err) {
				continue
			}
			return err // Even an ambiguous update must not authorize deletion.
		}
		for _, chunk := range candidates {
			if currentChunk(&chunk, d) {
				continue
			}
			if err := c.client.deleteSecret(ctx, c.namespace, chunk.Name, chunk.UID); err != nil && !k8serrors.IsNotFound(err) {
				return err
			}
		}
		if len(candidates) == gcBatchSize {
			return errGCIncomplete
		}
		return nil
	}
	return errors.New("state changed repeatedly during collection")
}

func currentChunk(chunk *corev1.Secret, d *descriptor) bool {
	return d != nil && chunk.Labels[revisionLabel] == strconv.FormatUint(d.Revision, 10) && chunk.Labels[uploadLabel] == d.Upload
}
