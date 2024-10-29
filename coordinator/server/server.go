/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// Package server contains the ClientAPI HTTP-REST and MarbleAPI gRPC server.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/edgelesssys/marblerun/coordinator/core"
	"github.com/edgelesssys/marblerun/coordinator/events"
	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"github.com/edgelesssys/marblerun/coordinator/server/handler"
	v1 "github.com/edgelesssys/marblerun/coordinator/server/v1"
	v2 "github.com/edgelesssys/marblerun/coordinator/server/v2"
	grpcprometheus "github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// RunMarbleServer starts a gRPC with the given Coordinator core.
// `address` is the desired TCP address like "localhost:0".
// The effective TCP address is returned via `addrChan`.
func RunMarbleServer(core *core.Core, addr string, addrChan chan string, errChan chan error, zapLogger *zap.Logger, promRegistry *prometheus.Registry) {
	tlsConfig := tls.Config{
		GetCertificate: core.GetTLSMarbleRootCertificate,
		// NOTE: we'll verify the cert later using the given quote
		ClientAuth: tls.RequireAnyClientCert,
	}
	creds := credentials.NewTLS(&tlsConfig)

	// Make sure that log statements internal to gRPC library are logged using the zapLogger as well.
	replaceGRPCLogger(zapLogger)

	grpcMetrics := grpcprometheus.NewServerMetrics()
	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainStreamInterceptor(
			logging.StreamServerInterceptor(middlewareLogger(zapLogger)),
			grpcMetrics.StreamServerInterceptor(),
		),
		grpc.ChainUnaryInterceptor(
			logging.UnaryServerInterceptor(middlewareLogger(zapLogger)),
			grpcMetrics.UnaryServerInterceptor(),
		),
	)

	rpc.RegisterMarbleServer(grpcServer, core)
	if promRegistry != nil {
		grpcMetrics.InitializeMetrics(grpcServer)
		promRegistry.MustRegister(grpcMetrics)
	}
	socket, err := net.Listen("tcp", addr)
	if err != nil {
		errChan <- err
		return
	}
	addrChan <- socket.Addr().String()
	err = grpcServer.Serve(socket)
	if err != nil {
		errChan <- err
	}
}

// CreateServeMux creates a mux that serves the client API.
func CreateServeMux(api handler.ClientAPI, promFactory *promauto.Factory, log *zap.Logger) serveMux {
	serverV1 := v1.NewServer(api)
	serverV2 := v2.NewServer(api)
	var router serveMux
	if promFactory != nil {
		muxRouter := newPromServeMux(promFactory, "server", "client_api")
		muxRouter.setMethodNotAllowedHandler(handler.MethodNotAllowedHandler)
		router = muxRouter
	} else {
		muxRouter := http.NewServeMux()
		muxRouter.HandleFunc("/", handler.MethodNotAllowedHandler)
		router = muxRouter
	}

	router.HandleFunc("/manifest", logDeprecated(handler.GetPost(serverV1.ManifestGet, serverV1.ManifestPost), log))
	router.HandleFunc("/update", logDeprecated(handler.GetPost(serverV1.UpdateGet, serverV1.UpdatePost), log))
	router.HandleFunc("/secrets", logDeprecated(handler.GetPost(serverV1.SecretsGet, serverV1.SecretsPost), log))
	router.HandleFunc("/status", logDeprecated(handler.GetPost(serverV1.StatusGet, handler.MethodNotAllowedHandler), log))
	router.HandleFunc("/quote", logDeprecated(handler.GetPost(serverV1.QuoteGet, handler.MethodNotAllowedHandler), log))
	router.HandleFunc("/recover", logDeprecated(handler.GetPost(handler.MethodNotAllowedHandler, serverV1.RecoverPost), log))

	v2Endpoint := "/api/v2"
	router.HandleFunc(v2Endpoint+"/manifest", handler.GetPost(serverV2.ManifestGet, serverV2.ManifestPost))
	router.HandleFunc(v2Endpoint+"/update", handler.GetPost(serverV2.UpdateGet, serverV2.UpdatePost))
	router.HandleFunc(v2Endpoint+"/secrets", handler.GetPost(serverV2.SecretsGet, serverV2.SecretsPost))
	router.HandleFunc(v2Endpoint+"/status", handler.GetPost(serverV2.StatusGet, handler.MethodNotAllowedHandler))
	router.HandleFunc(v2Endpoint+"/quote", handler.GetPost(serverV2.QuoteGet, handler.MethodNotAllowedHandler))
	router.HandleFunc(v2Endpoint+"/recover", handler.GetPost(handler.MethodNotAllowedHandler, serverV2.RecoverPost))
	router.HandleFunc(v2Endpoint+"/sign-quote", handler.GetPost(handler.MethodNotAllowedHandler, serverV2.SignQuotePost))
	router.HandleFunc(v2Endpoint+"/monotonic-counter", handler.GetPost(handler.MethodNotAllowedHandler, serverV2.MonotonicCounterPost))
	return router
}

// RunClientServer runs a HTTP server serving mux.
func RunClientServer(mux http.Handler, address string, tlsConfig *tls.Config, zapLogger *zap.Logger) {
	server := http.Server{
		Addr:      address,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}
	zapLogger.Info("Starting client https server", zap.String("address", address))
	err := server.ListenAndServeTLS("", "")
	zapLogger.Warn(err.Error())
}

// RunPrometheusServer runs a HTTP server handling the prometheus metrics endpoint.
func RunPrometheusServer(address string, zapLogger *zap.Logger, reg *prometheus.Registry, eventlog *events.Log) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.InstrumentMetricHandler(reg, promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg})))
	mux.Handle("/events", eventlog.Handler())
	zapLogger.Info("Starting prometheus /metrics endpoint", zap.String("address", address))
	err := http.ListenAndServe(address, mux)
	zapLogger.Warn(err.Error())
}

func middlewareLogger(log *zap.Logger) logging.Logger {
	return logging.LoggerFunc(func(_ context.Context, lvl logging.Level, msg string, fields ...any) {
		f := make([]zap.Field, 0, len(fields)/2)

		for i := 0; i < len(fields); i += 2 {
			key := fields[i]
			value := fields[i+1]

			switch v := value.(type) {
			case string:
				f = append(f, zap.String(key.(string), v))
			case int:
				f = append(f, zap.Int(key.(string), v))
			case bool:
				f = append(f, zap.Bool(key.(string), v))
			default:
				f = append(f, zap.Any(key.(string), v))
			}
		}

		logger := log.WithOptions(zap.AddCallerSkip(1)).With(f...)

		switch lvl {
		case logging.LevelDebug:
			logger.Debug(msg)
		case logging.LevelInfo:
			logger.Info(msg)
		case logging.LevelWarn:
			logger.Warn(msg)
		case logging.LevelError:
			logger.Error(msg)
		default:
			panic(fmt.Sprintf("unknown level %v", lvl))
		}
	})
}

func logDeprecated(handler func(http.ResponseWriter, *http.Request), log *zap.Logger) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Info(
			fmt.Sprintf("Usage of deprecated API endpoint. Consider using /api/v2/%s instead", strings.TrimPrefix(r.URL.Path, "/")),
			zap.String("path", r.URL.Path),
		)
		handler(w, r)
	}
}
