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

type CoreMetrics struct {
	storeWarpper *StoreWrapperMetrics
	marbleAPI    *MarbleAPIMetrics
}

func NewCoreMetrics(factory *promauto.Factory, namespace string) *CoreMetrics {
	if factory == nil {
		return &CoreMetrics{
			storeWarpper: nil,
			marbleAPI:    nil,
		}
	}
	return &CoreMetrics{
		storeWarpper: NewStoreWrapperMetrics(factory, namespace, ""),
		marbleAPI:    NewMarbleAPIMetrics(factory, namespace, ""),
	}
}

type MarbleAPIMetrics struct {
	activation        *prometheus.CounterVec
	activationSuccess *prometheus.CounterVec
}

func NewMarbleAPIMetrics(factory *promauto.Factory, namespace string, subsystem string) *MarbleAPIMetrics {
	return &MarbleAPIMetrics{
		activation: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "marble_activation_total",
				Help:      "Number of Marble activation attempts.",
			},
			[]string{"type", "uuid"},
		),
		activationSuccess: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "marble_activation_success_total",
				Help:      "Number of successful Marble activations.",
			},
			[]string{"type", "uuid"},
		),
	}
}

type StoreWrapperMetrics struct {
	coordinatorState prometheus.Gauge
}

func NewStoreWrapperMetrics(factory *promauto.Factory, namespace string, subsystem string) *StoreWrapperMetrics {
	return &StoreWrapperMetrics{
		coordinatorState: factory.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "state",
				Help:      "State of the Coordinator.",
			}),
	}
}
