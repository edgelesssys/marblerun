/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/edgelesssys/marblerun/injector"
	"github.com/edgelesssys/marblerun/internal/logging"
	"go.uber.org/zap"
)

// Version of the injector.
var Version = "0.0.0" // Don't touch! Automatically injected at build-time.

// GitCommit is the git commit hash.
var GitCommit = "0000000000000000000000000000000000000000" // Don't touch! Automatically injected at build-time.

func main() {
	var certFile string
	var keyFile string
	var addr string
	var clusterDomain string
	var sgxResource string
	flag.StringVar(&addr, "coordAddr", "coordinator-mesh-api.marblerun:2001", "Address of the MarbleRun coordinator")
	flag.StringVar(&certFile, "tlsCertFile", "/etc/webhook/certs/tls.crt", "File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&keyFile, "tlsKeyFile", "/etc/webhook/certs/tls.key", "File containing the x509 private key to --tlsCertFile.")
	flag.StringVar(&clusterDomain, "clusterDomain", "cluster.local", "Domain name of the kubernetes cluster")
	flag.StringVar(&sgxResource, "sgxResource", "sgx.intel.com/epc", "Defines the resource/toleration to inject, this needs to be exposed on a node through a device plugin")

	flag.Parse()

	log, err := logging.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create logger: %s\n", err)
		os.Exit(1)
	}
	defer log.Sync() // flushes buffer, if any
	log.Info("Starting marble-injector webhook", zap.String("version", Version), zap.String("commit", GitCommit))

	mux := http.NewServeMux()
	w := injector.New(addr, clusterDomain, sgxResource, log)

	mux.HandleFunc("/mutate", w.HandleMutate)

	s := &http.Server{
		// Address forwarding to 443 should be handled by the marble-injector service object
		Addr:    ":8443",
		Handler: mux,
		TLSConfig: &tls.Config{
			GetCertificate: loadWebhookCert(certFile, keyFile),
		},
		ErrorLog: logging.NewWrapper(log),
	}

	log.Info("Starting Server")
	err = s.ListenAndServeTLS("", "")
	log.Fatal("Failed running server", zap.Error(err))
}

// loadWebhookCert loads the certificate and key file for the webhook server.
// We need to use this function since the certificate may be updated by cert-manager,
// requiring us to reload the certificate.
func loadWebhookCert(certFile, keyFile string) func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed loading tls key pair: %w", err)
		}

		return &pair, nil
	}
}
