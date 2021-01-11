// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package server contains the ClientAPI HTTP-REST and MarbleAPI gRPC server.
package server

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"os"

	"github.com/edgelesssys/marblerun/coordinator/core"
	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"github.com/gorilla/handlers"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type certQuoteResp struct {
	Cert  string
	Quote []byte
}
type statusResp struct {
	Code   int
	Status string
}
type manifestSignatureResp struct {
	ManifestSignature string
}

// Contains RSA-encrypted AES state sealing key with public key specified by user in manifest
type recoveryDataResp struct {
	EncryptionKey string
}

// RunMarbleServer starts a gRPC with the given Coordinator core.
// `address` is the desired TCP address like "localhost:0".
// The effective TCP address is returned via `addrChan`.
func RunMarbleServer(core *core.Core, addr string, addrChan chan string, errChan chan error, zapLogger *zap.Logger) {
	tlsConfig := tls.Config{
		GetCertificate: core.GetTLSCertificate,
		// NOTE: we'll verify the cert later using the given quote
		ClientAuth: tls.RequireAnyClientCert,
	}
	creds := credentials.NewTLS(&tlsConfig)

	// Make sure that log statements internal to gRPC library are logged using the zapLogger as well.
	grpc_zap.ReplaceGrpcLoggerV2(zapLogger)

	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(
			grpc_ctxtags.StreamServerInterceptor(),
			grpc_zap.StreamServerInterceptor(zapLogger),
			grpc_prometheus.StreamServerInterceptor,
		)),
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			grpc_ctxtags.UnaryServerInterceptor(),
			grpc_zap.UnaryServerInterceptor(zapLogger),
			grpc_prometheus.UnaryServerInterceptor,
		)),
	)

	rpc.RegisterMarbleServer(grpcServer, core)
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
func CreateServeMux(cc core.ClientCore) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			statusCode, status, err := cc.GetStatus(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, statusResp{statusCode, status})
		default:
			http.Error(w, "", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/manifest", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			signature := cc.GetManifestSignature(r.Context())
			writeJSON(w, manifestSignatureResp{hex.EncodeToString(signature)})
		case http.MethodPost:
			manifest, err := ioutil.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			recoveryDataBytes, err := cc.SetManifest(r.Context(), manifest)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// If a recovery key has been set, include recovery data as response. If not, leave response empty.
			if recoveryDataBytes != nil {
				encodedRecoveryData := base64.StdEncoding.EncodeToString(recoveryDataBytes)
				writeJSON(w, recoveryDataResp{encodedRecoveryData})
			}
		default:
			http.Error(w, "", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/quote", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cert, quote, err := cc.GetCertQuote(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, certQuoteResp{cert, quote})
		default:
			http.Error(w, "", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/recover", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			key, err := ioutil.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if err = cc.Recover(r.Context(), key); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		default:
			http.Error(w, "", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/update", func(w http.ResponseWriter, r *http.Request) {
		clientCerts := r.TLS.PeerCertificates
		verifiedAdmin := cc.VerifyAdmin(r.Context(), clientCerts)

		// Abort if no admin client certificate was provided
		if verifiedAdmin != true {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		switch r.Method {
		case http.MethodPost:
			updateManifest, err := ioutil.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			err = cc.UpdateManifest(r.Context(), updateManifest)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		default:
			http.Error(w, "", http.StatusMethodNotAllowed)
		}
	})

	return mux
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// RunClientServer runs a HTTP server serving mux.
func RunClientServer(mux *http.ServeMux, address string, tlsConfig *tls.Config, zapLogger *zap.Logger) {
	loggedRouter := handlers.LoggingHandler(os.Stdout, mux)
	server := http.Server{
		Addr:      address,
		Handler:   loggedRouter,
		TLSConfig: tlsConfig,
	}
	zapLogger.Info("starting client https server", zap.String("address", address))
	err := server.ListenAndServeTLS("", "")
	zapLogger.Warn(err.Error())
}

// RunPrometheusServer runs a HTTP server handling the prometheus metrics endpoint
func RunPrometheusServer(address string, zapLogger *zap.Logger) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	zapLogger.Info("starting prometheus /metrics endpoint", zap.String("address", address))
	err := http.ListenAndServe(address, mux)
	zapLogger.Warn(err.Error())
}
