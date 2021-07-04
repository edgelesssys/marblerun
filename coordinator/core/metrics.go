// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type coreMetrics struct {
	coordinatorState prometheus.Gauge
	marbleAPI        *marbleAPIMetrics
}

func newCoreMetrics(factory *promauto.Factory, namespace string) *coreMetrics {
	if factory == nil {
		return nil
	}
	return &coreMetrics{
		coordinatorState: factory.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "state",
				Help:      "State of the Coordinator.",
			}),
		marbleAPI: newMarbleAPIMetrics(factory, namespace),
	}
}

type marbleAPIMetrics struct {
	activation        *prometheus.CounterVec
	activationSuccess *prometheus.CounterVec
}

func newMarbleAPIMetrics(factory *promauto.Factory, namespace string) *marbleAPIMetrics {
	return &marbleAPIMetrics{
		activation: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "marble_activations_total",
				Help:      "Number of Marble activation attempts.",
			},
			[]string{"type", "uuid"},
		),
		activationSuccess: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "marble_activations_success_total",
				Help:      "Number of successful Marble activations.",
			},
			[]string{"type", "uuid"},
		),
	}
}
