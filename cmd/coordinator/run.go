// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"os"
	"strings"

	"github.com/edgelesssys/marblerun/coordinator/clientapi"
	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/core"
	"github.com/edgelesssys/marblerun/coordinator/events"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/server"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
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
	devMode := util.Getenv(constants.DevMode, constants.DevModeDefault) == "1"

	// Setup logging with Zap Logger
	// Development Logger shows a stacktrace for warnings & errors, Production Logger only for errors
	var log *zap.Logger
	var err error
	if devMode {
		log, err = zap.NewDevelopment()
	} else {
		log, err = zap.NewProduction()
	}
	if err != nil {
		panic(err)
	}
	defer log.Sync() // flushes buffer, if any

	log.Info("Starting coordinator", zap.String("version", Version), zap.String("commit", GitCommit))

	// fetching env vars
	dnsNamesString := util.Getenv(constants.DNSNames, constants.DNSNamesDefault)
	dnsNames := strings.Split(dnsNamesString, ",")
	clientServerAddr := util.Getenv(constants.ClientAddr, constants.ClientAddrDefault)
	meshServerAddr := util.Getenv(constants.MeshAddr, constants.MeshAddrDefault)
	promServerAddr := os.Getenv(constants.PromAddr)
	startupManifest := os.Getenv(constants.StartupManifest)

	// Create Prometheus resources and start the Prometheus server.
	eventlog := events.NewLog()
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
		go server.RunPrometheusServer(promServerAddr, log, promRegistry, eventlog)
	}

	store := stdstore.New(sealer)

	// creating core
	log.Info("creating the Core object")
	if err := os.MkdirAll(sealDir, 0o700); err != nil {
		log.Fatal("Cannot create or access sealdir. Please check the permissions for the specified path.", zap.Error(err))
	}
	co, err := core.NewCore(dnsNames, validator, issuer, store, recovery, log, promFactoryPtr, eventlog)
	if err != nil {
		if _, ok := err.(core.QuoteError); !ok || !devMode {
			log.Fatal("Cannot create Coordinator core", zap.Error(err))
		}
	}

	clientServer, err := clientapi.New(store, recovery, co, log)
	if err != nil {
		log.Fatal("Creating client server failed", zap.Error(err))
	}

	// startup manifest
	if startupManifest != "" {
		log.Info("Setting startup manifest")
		content, err := os.ReadFile(startupManifest)
		if err != nil {
			log.Fatal("Cannot read startup manifest", zap.Error(err))
		}
		if _, err := clientServer.SetManifest(content); err != nil {
			log.Fatal("Cannot set startup manifest", zap.Error(err))
		}
	}

	// start client server
	log.Info("starting the client server")
	mux := server.CreateServeMux(clientServer, promFactoryPtr)
	clientServerTLSConfig, err := co.GetTLSConfig()
	if err != nil {
		log.Fatal("Cannot create TLS credentials", zap.Error(err))
	}
	go server.RunClientServer(mux, clientServerAddr, clientServerTLSConfig, log)

	// run marble server
	log.Info("Starting the marble server")
	addrChan := make(chan string)
	errChan := make(chan error)
	go server.RunMarbleServer(co, meshServerAddr, addrChan, errChan, log, promRegistry)
	for {
		select {
		case err := <-errChan:
			if err != nil {
				log.Fatal("Error during execution", zap.Error(err))
			}
			return
		case grpcAddr := <-addrChan:
			log.Info("Started gRPC server", zap.String("grpcAddr", grpcAddr))
		}
	}
}
