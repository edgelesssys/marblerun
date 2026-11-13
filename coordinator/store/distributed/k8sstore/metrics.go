/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package k8sstore

import "github.com/prometheus/client_golang/prometheus"

type metrics struct {
	size         prometheus.Gauge
	revision     prometheus.Gauge
	gcCandidates prometheus.Gauge
	gcErrors     prometheus.Counter
	gcDuration   prometheus.Histogram
}

func newMetrics(registry prometheus.Registerer) metrics {
	if registry == nil {
		return metrics{}
	}
	m := metrics{
		size:         prometheus.NewGauge(prometheus.GaugeOpts{Name: "coordinator_state_bytes", Help: "Last observed sealed state and wrapped key size in bytes."}),
		revision:     prometheus.NewGauge(prometheus.GaugeOpts{Name: "coordinator_state_revision", Help: "Last observed committed state revision."}),
		gcCandidates: prometheus.NewGauge(prometheus.GaugeOpts{Name: "coordinator_state_gc_candidates", Help: "Eligible chunks in the last bounded GC batch (not a total orphan count)."}),
		gcErrors:     prometheus.NewCounter(prometheus.CounterOpts{Name: "coordinator_state_gc_errors_total", Help: "Failed state chunk collection attempts."}),
		gcDuration:   prometheus.NewHistogram(prometheus.HistogramOpts{Name: "coordinator_state_gc_duration_seconds", Help: "Time spent collecting state chunks."}),
	}
	registry.MustRegister(m.size, m.revision, m.gcCandidates, m.gcErrors, m.gcDuration)
	return m
}

func (c *Client) observeState(revision uint64, size int) {
	if c.metrics.size != nil {
		c.metrics.size.Set(float64(size))
		c.metrics.revision.Set(float64(revision))
	}
}
