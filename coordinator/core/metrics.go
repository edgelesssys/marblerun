// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	dto "github.com/prometheus/client_model/go"
)

type coreMetrics struct {
	coordinatorState prometheus.GaugeFunc
	marbleAPI        *marbleAPIMetrics
}

func newCoreMetrics(factory *promauto.Factory, core *Core, namespace string) *coreMetrics {
	if factory == nil {
		return &coreMetrics{
			coordinatorState: nil,
			marbleAPI:        newNullMarbleAPIMetrics(),
		}
	}
	return &coreMetrics{
		coordinatorState: factory.NewGaugeFunc(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "state",
				Help:      "State of the Coordinator.",
			},
			func() float64 {
				state, err := core.data.getState()
				if err != nil {
					return float64(0)
				}
				return float64(state)
			}),
		marbleAPI: newMarbleAPIMetrics(factory, namespace),
	}
}

type marbleAPIMetrics struct {
	activation        CounterVec
	activationSuccess CounterVec
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

func newNullMarbleAPIMetrics() *marbleAPIMetrics {
	return &marbleAPIMetrics{
		activation:        NullCounterVec{},
		activationSuccess: NullCounterVec{},
	}
}

type NullCollector struct{}

func (NullCollector) Describe(chan<- *prometheus.Desc) {}
func (NullCollector) Collect(chan<- prometheus.Metric) {}

type NullMetric struct{}

func (NullMetric) Desc() *prometheus.Desc  { return nil }
func (NullMetric) Write(*dto.Metric) error { return nil }

type NullCounter struct {
	NullMetric
	NullCollector
}

func (NullCounter) Inc()        {}
func (NullCounter) Add(float64) {}

type BaseVec interface {
	prometheus.Collector

	Delete(labels prometheus.Labels) bool
	DeleteLabelValues(lvs ...string) bool
	Reset()
}

type CounterVec interface {
	BaseVec

	GetMetricWith(labels prometheus.Labels) (prometheus.Counter, error)
	GetMetricWithLabelValues(lvs ...string) (prometheus.Counter, error)
	With(labels prometheus.Labels) prometheus.Counter
	WithLabelValues(lvs ...string) prometheus.Counter
}

type NullBaseVec struct {
	NullCollector
}

func (NullBaseVec) Delete(labels prometheus.Labels) bool { return false }
func (NullBaseVec) DeleteLabelValues(lvs ...string) bool { return false }
func (NullBaseVec) Reset()                               {}

type NullCounterVec struct {
	NullBaseVec
}

func (NullCounterVec) GetMetricWith(labels prometheus.Labels) (prometheus.Counter, error) {
	return NullCounter{}, nil
}

func (NullCounterVec) GetMetricWithLabelValues(lvs ...string) (prometheus.Counter, error) {
	return NullCounter{}, nil
}
func (NullCounterVec) With(labels prometheus.Labels) prometheus.Counter { return NullCounter{} }
func (NullCounterVec) WithLabelValues(lvs ...string) prometheus.Counter { return NullCounter{} }
