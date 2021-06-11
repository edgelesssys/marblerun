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
	"fmt"
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

// GeneralResponse is a wrapper for all our REST API responses to follow the JSend style: https://github.com/omniti-labs/jsend
type GeneralResponse struct {
	Status  string      `json:"status"`
	Data    interface{} `json:"data"`
	Message string      `json:"message,omitempty"` // only used when status = "error"
}
type certQuoteResp struct {
	Cert  string
	Quote []byte
}
type statusResp struct {
	StatusCode    int
	StatusMessage string
}
type manifestSignatureResp struct {
	ManifestSignature string
}

// Contains RSA-encrypted AES state sealing key with public key specified by user in manifest
type recoveryDataResp struct {
	RecoverySecrets map[string]string
}

type recoveryStatusResp struct {
	StatusMessage string
}

// RunMarbleServer starts a gRPC with the given Coordinator core.
// `address` is the desired TCP address like "localhost:0".
// The effective TCP address is returned via `addrChan`.
func RunMarbleServer(core *core.Core, addr string, addrChan chan string, errChan chan error, zapLogger *zap.Logger) {
	tlsConfig := tls.Config{
		GetCertificate: core.GetTLSMarbleRootCertificate,
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
				writeJSONError(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, statusResp{statusCode, status})
		default:
			writeJSONError(w, "", http.StatusMethodNotAllowed)
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
				writeJSONError(w, err.Error(), http.StatusInternalServerError)
				return
			}
			recoverySecretMap, err := cc.SetManifest(r.Context(), manifest)

			if err != nil {
				writeJSONError(w, err.Error(), http.StatusBadRequest)
				return
			}

			// If recovery data is set, return it
			if len(recoverySecretMap) > 0 {
				secretMap := make(map[string]string, len(recoverySecretMap))
				for name, secret := range recoverySecretMap {
					secretMap[name] = base64.StdEncoding.EncodeToString(secret)
				}
				writeJSON(w, recoveryDataResp{secretMap})
			} else {
				writeJSON(w, nil)
			}

		default:
			writeJSONError(w, "", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/quote", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cert, quote, err := cc.GetCertQuote(r.Context())
			if err != nil {
				writeJSONError(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, certQuoteResp{cert, quote})
		default:
			writeJSONError(w, "", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/recover", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			key, err := ioutil.ReadAll(r.Body)
			if err != nil {
				writeJSONError(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Perform recover and receive amount of remaining secrets (for multi-party recovery)
			remaining, err := cc.Recover(r.Context(), key)

			if err != nil {
				writeJSONError(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Construct status message based on remaining keys
			var statusMessage string
			if remaining != 0 {
				statusMessage = fmt.Sprintf("Secret was processed successfully. Upload the next secret. Remaining secrets: %d", remaining)
			} else {
				statusMessage = "Recovery successful."
			}

			writeJSON(w, recoveryStatusResp{statusMessage})

		default:
			writeJSONError(w, "", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/update", func(w http.ResponseWriter, r *http.Request) {
		// Abort if no user client certificate was provided
		if r.TLS == nil {
			writeJSONError(w, "no client certificate provided", http.StatusUnauthorized)
			return
		}
		user, err := cc.VerifyUser(r.Context(), r.TLS.PeerCertificates)
		if err != nil {
			writeJSONError(w, "unauthorized user", http.StatusUnauthorized)
			return
		}

		switch r.Method {
		case http.MethodPost:
			updateManifest, err := ioutil.ReadAll(r.Body)
			if err != nil {
				writeJSONError(w, err.Error(), http.StatusInternalServerError)
				return
			}
			err = cc.UpdateManifest(r.Context(), updateManifest, user)
			if err != nil {
				writeJSONError(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, nil)
		default:
			writeJSONError(w, "", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		// Abort if no user client certificate was provided
		if r.TLS == nil {
			writeJSONError(w, "no client certificate provided", http.StatusUnauthorized)
			return
		}
		user, err := cc.VerifyUser(r.Context(), r.TLS.PeerCertificates)
		if err != nil {
			writeJSONError(w, "unauthorized user", http.StatusUnauthorized)
			return
		}

		switch r.Method {
		case http.MethodPost:
			writeJSONError(w, "not implemented", http.StatusBadRequest)
			return
		case http.MethodGet:
			// Secrets are requested via the query string in the form of ?s=<secret_one>&s=<secret_two>&s=...
			requestedSecrets := r.URL.Query()["s"]
			if len(requestedSecrets) <= 0 {
				writeJSONError(w, "invalid query", http.StatusBadRequest)
				return
			}
			for _, req := range requestedSecrets {
				if len(req) <= 0 {
					writeJSONError(w, "malformed query string", http.StatusBadRequest)
					return
				}
			}
			response, err := cc.GetSecrets(r.Context(), requestedSecrets, user)
			if err != nil {
				writeJSONError(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, response)
		default:
			writeJSONError(w, "", http.StatusMethodNotAllowed)
		}
	})

	return mux
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	dataToReturn := GeneralResponse{Status: "success", Data: v}
	if err := json.NewEncoder(w).Encode(dataToReturn); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func writeJSONError(w http.ResponseWriter, errorString string, httpErrorCode int) {
	marshalledJSON, err := json.Marshal(GeneralResponse{Status: "error", Message: errorString})
	// Only fall back to non-JSON error when we cannot even marshal the error (which is pretty bad)
	if err != nil {
		http.Error(w, errorString, httpErrorCode)
	}
	http.Error(w, string(marshalledJSON), httpErrorCode)
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
