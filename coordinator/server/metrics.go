/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

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
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// httpMetrics is a struct of metrics for Prometheus to collect for each endpoint.
type httpMetrics struct {
	request      *prometheus.CounterVec
	duration     *prometheus.HistogramVec
	requestSize  *prometheus.HistogramVec
	responseSize *prometheus.HistogramVec
	inflight     prometheus.Gauge
}

// newHttpMetrics creates a new collection of HTTP related Prometheus metrics,
// and registres them using the given factory.
func newHTTPMetrics(factory *promauto.Factory, namespace string, subsystem string, constLabels map[string]string) *httpMetrics {
	return &httpMetrics{
		request: factory.NewCounterVec(
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

// promServeMux is a wrapper around mux.Router with additional instrumentation to
// gather Prometheus metrics.
type promServeMux struct {
	router      *http.ServeMux
	promFactory *promauto.Factory
	metrics     map[string]*httpMetrics
	namespace   string
	subsystem   string
}

// newPromServeMux allocates and returns a new PromServeMux
// namespace and subsystem are used to name the exposed metrics.
func newPromServeMux(factory *promauto.Factory, namespace string, subsystem string) *promServeMux {
	return &promServeMux{
		router:      http.NewServeMux(),
		promFactory: factory,
		metrics:     make(map[string]*httpMetrics),
		namespace:   namespace,
		subsystem:   subsystem + "_http",
	}
}

// Handle is a wrapper around (*mux.Router) Handle form the http package
// A chain of prometheus instrumentation collects metrics for the given handler.
func (p *promServeMux) Handle(pattern string, handler http.Handler) {
	if p.metrics[pattern] == nil {
		constLabels := map[string]string{
			"path": pattern,
		}
		p.metrics[pattern] = newHTTPMetrics(p.promFactory, p.namespace, p.subsystem, constLabels)
	}
	p.router.Handle(pattern, p.metricsMiddleware(pattern, handler))
}

// HandleFunc registers the handler function for the given pattern.
func (p *promServeMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	if handler == nil {
		panic("promServerMux: http: nil handler")
	}
	p.Handle(pattern, http.HandlerFunc(handler))
}

// ServeHTTP is a wrapper around (*mux.Router) ServeHttp form the http package.
func (p *promServeMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.router.ServeHTTP(w, r)
}

// metricsMiddelware returns the handed next handler wrapped in a bunch of prometheus metric handlers.
func (p *promServeMux) metricsMiddleware(pattern string, next http.Handler) http.Handler {
	return promhttp.InstrumentHandlerDuration(p.metrics[pattern].duration,
		promhttp.InstrumentHandlerCounter(p.metrics[pattern].request,
			promhttp.InstrumentHandlerRequestSize(p.metrics[pattern].requestSize,
				promhttp.InstrumentHandlerResponseSize(p.metrics[pattern].responseSize,
					promhttp.InstrumentHandlerInFlight(p.metrics[pattern].inflight, next),
				),
			),
		),
	)
}

// setMethodNOtAllowedHandler sets f as instrumented handler for the mux.Router.
func (p *promServeMux) setMethodNotAllowedHandler(f func(http.ResponseWriter, *http.Request)) {
	p.router.HandleFunc(
		"/",
		func(w http.ResponseWriter, r *http.Request) {
			handler := p.metricsMiddleware(r.URL.Path, http.HandlerFunc(f))
			handler.ServeHTTP(w, r)
		},
	)
}
