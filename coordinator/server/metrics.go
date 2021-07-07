// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package server

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// serveMux is an interface of an HTTP request multiplexer.
type serveMux interface {
	Handle(pattern string, handler http.Handler)
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
	Handler(r *http.Request) (h http.Handler, pattern string)
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

//httpMetrics is a struct of metrics for Prometheus to collect for each endpoint.
type httpMetrics struct {
	reqest       *prometheus.CounterVec
	duration     *prometheus.HistogramVec
	requestSize  *prometheus.HistogramVec
	responseSize *prometheus.HistogramVec
	inflight     prometheus.Gauge
}

// newHttpMetrics creates a new collection of HTTP related Prometheus metrics,
// and registres them using the given factory.
func newHttpMetrics(factory *promauto.Factory, namespace string, subsystem string, constLabels map[string]string) *httpMetrics {
	return &httpMetrics{
		reqest: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace:   namespace,
				Subsystem:   subsystem,
				Name:        "request_total",
				Help:        "Total number of requests received.",
				ConstLabels: constLabels,
			},
			[]string{"code", "method"},
		),
		duration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace:   namespace,
				Subsystem:   subsystem,
				Name:        "request_duration_histogram_seconds",
				Help:        "Request time duration.",
				ConstLabels: constLabels,
				Buckets:     []float64{0.005, 0.025, 0.1, 0.5, 1, 2.5, 5},
			},
			[]string{"method"},
		),
		requestSize: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace:   namespace,
				Subsystem:   subsystem,
				Name:        "request_size_histogram_bytes",
				Help:        "Request size in byte.",
				ConstLabels: constLabels,
				Buckets:     []float64{100, 1000, 2000, 5000, 10000},
			},
			[]string{},
		),
		responseSize: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace:   namespace,
				Subsystem:   subsystem,
				Name:        "response_size_histogram_bytes",
				Help:        "Response size in byte.",
				ConstLabels: constLabels,
				Buckets:     []float64{100, 1000, 2000, 5000, 10000},
			},
			[]string{},
		),
		inflight: factory.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   namespace,
				Subsystem:   subsystem,
				Name:        "in_flight_requests",
				Help:        "Number of http requests which are currently running.",
				ConstLabels: constLabels,
			},
		),
	}
}

// promServeMux is a wrapper around http.ServeMux with additional instrumentation to
// gather Prometheus metrics
type promServeMux struct {
	serveMux    http.ServeMux
	promFactory *promauto.Factory
	metrics     map[string]*httpMetrics
	namespace   string
	subsystem   string
}

// newPromServeMux allocates and returns a new PromServeMux
// namespace and subsystem are used to name the exposed metrics
func newPromServeMux(factory *promauto.Factory, namespace string, subsystem string) *promServeMux {
	return &promServeMux{
		serveMux:    *http.NewServeMux(),
		promFactory: factory,
		metrics:     make(map[string]*httpMetrics),
		namespace:   namespace,
		subsystem:   subsystem + "_http",
	}
}

// Handle is a wrapper around (*http.ServeMux) Handle form the http package
// A chain of prometheus instrumentation collects metrics for the given handler.
func (mux *promServeMux) Handle(pattern string, handler http.Handler) {
	if mux.metrics[pattern] == nil {
		constLabels := map[string]string{
			"path": pattern,
		}
		mux.metrics[pattern] = newHttpMetrics(mux.promFactory, mux.namespace, mux.subsystem, constLabels)
	}
	chain := promhttp.InstrumentHandlerDuration(mux.metrics[pattern].duration,
		promhttp.InstrumentHandlerCounter(mux.metrics[pattern].reqest,
			promhttp.InstrumentHandlerRequestSize(mux.metrics[pattern].requestSize,
				promhttp.InstrumentHandlerResponseSize(mux.metrics[pattern].responseSize,
					promhttp.InstrumentHandlerInFlight(mux.metrics[pattern].inflight,
						handler,
					),
				),
			),
		),
	)
	mux.serveMux.Handle(pattern, chain)
}

// HandleFunc registers the handler function for the given pattern.
func (mux *promServeMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	if handler == nil {
		panic("promServerMux: http: nil handler")
	}
	mux.Handle(pattern, http.HandlerFunc(handler))
}

// ServeHTTP is a wrapper around (*http.ServeMux) ServeHttp form the http package.
func (mux *promServeMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux.serveMux.ServeHTTP(w, r)
}

// Handler is a wrapper around (*http.ServeMux) Handler form the http package.
func (mux *promServeMux) Handler(r *http.Request) (h http.Handler, pattern string) {
	return mux.serveMux.Handler(r)
}
