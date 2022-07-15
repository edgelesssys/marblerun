// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/edgelesssys/marblerun/coordinator/config"
	"github.com/edgelesssys/marblerun/coordinator/core"
	"github.com/edgelesssys/marblerun/coordinator/events"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/server"
	"github.com/edgelesssys/marblerun/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

// Version is the Coordinator version.
var Version = "0.0.0" // Don't touch! Automatically injected at build-time.

// GitCommit is the git commit hash.
var GitCommit = "0000000000000000000000000000000000000000" // Don't touch! Automatically injected at build-time.

func run(validator quote.Validator, issuer quote.Issuer, sealDir string, sealer seal.Sealer, recovery recovery.Recovery) {
	devModeStr := util.Getenv(config.DevMode, config.DevModeDefault)
	devMode := devModeStr == "1"

	// Setup logging with Zap Logger
	// Development Logger shows a stacktrace for warnings & errors, Production Logger only for errors
	var zapLogger *zap.Logger
	var err error
	if devMode {
		zapLogger, err = zap.NewDevelopment()
	} else {
		zapLogger, err = zap.NewProduction()
	}
	if err != nil {
		log.Fatal(err)
	}
	defer zapLogger.Sync() // flushes buffer, if any

	zapLogger.Info("starting coordinator", zap.String("version", Version), zap.String("commit", GitCommit))

	// fetching env vars
	dnsNamesString := util.Getenv(config.DNSNames, config.DNSNamesDefault)
	dnsNames := strings.Split(dnsNamesString, ",")
	clientServerAddr := util.Getenv(config.ClientAddr, config.ClientAddrDefault)
	meshServerAddr := util.Getenv(config.MeshAddr, config.MeshAddrDefault)
	promServerAddr := os.Getenv(config.PromAddr)
	startupManifest := os.Getenv(config.StartupManifest)

	// Create Prometheus resources and start the Prometheus server.
	var eventlog = events.NewLog()
	var promRegistry *prometheus.Registry
	var promFactoryPtr *promauto.Factory
	if promServerAddr != "" {
		promRegistry = prometheus.NewRegistry()
		promFactory := promauto.With(promRegistry)
		promFactoryPtr = &promFactory
		promFactory.NewGauge(prometheus.GaugeOpts{
			Namespace: "coordinator",
			Name:      "version_info",
			Help:      "Version information of the coordinator.",
			ConstLabels: map[string]string{
				"version": Version,
				"commit":  GitCommit,
			},
		})
		go server.RunPrometheusServer(promServerAddr, zapLogger, promRegistry, eventlog)
	}

	// creating core
	zapLogger.Info("creating the Core object")
	if err := os.MkdirAll(sealDir, 0o700); err != nil {
		zapLogger.Fatal("Cannot create or access sealdir. Please check the permissions for the specified path.", zap.Error(err))
	}
	co, err := core.NewCore(dnsNames, validator, issuer, sealer, recovery, zapLogger, promFactoryPtr, eventlog)
	if err != nil {
		if _, ok := err.(core.QuoteError); !ok || !devMode {
			zapLogger.Fatal("Cannot create Coordinator core", zap.Error(err))
		}
	}

	// startup manifest
	if startupManifest != "" {
		zapLogger.Info("setting startup manifest")
		content, err := ioutil.ReadFile(startupManifest)
		if err != nil {
			zapLogger.Fatal("Cannot read startup manifest", zap.Error(err))
		}
		if _, err := co.SetManifest(context.TODO(), content); err != nil {
			zapLogger.Fatal("Cannot set startup manifest", zap.Error(err))
		}
	}

	// start client server
	zapLogger.Info("starting the client server")
	mux := server.CreateServeMux(co, promFactoryPtr)
	clientServerTLSConfig, err := co.GetTLSConfig()
	if err != nil {
		zapLogger.Fatal("Cannot create TLS credentials", zap.Error(err))
	}
	go server.RunClientServer(mux, clientServerAddr, clientServerTLSConfig, zapLogger)

	// run marble server
	zapLogger.Info("starting the marble server")
	addrChan := make(chan string)
	errChan := make(chan error)
	go server.RunMarbleServer(co, meshServerAddr, addrChan, errChan, zapLogger, promRegistry)
	for {
		select {
		case err := <-errChan:
			if err != nil {
				zapLogger.Fatal("Error during execution", zap.Error(err))
			}
			return
		case grpcAddr := <-addrChan:
			zapLogger.Info("started gRPC server", zap.String("grpcAddr", grpcAddr))
		}
	}
}
