/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"strings"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/enclave"
	"github.com/edgelesssys/marblerun/coordinator/clientapi"
	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/core"
	"github.com/edgelesssys/marblerun/coordinator/distributor"
	"github.com/edgelesssys/marblerun/coordinator/distributor/keyclient"
	"github.com/edgelesssys/marblerun/coordinator/distributor/keyserver"
	"github.com/edgelesssys/marblerun/coordinator/events"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	dseal "github.com/edgelesssys/marblerun/coordinator/seal/distributed"
	"github.com/edgelesssys/marblerun/coordinator/server"
	"github.com/edgelesssys/marblerun/coordinator/store"
	dstore "github.com/edgelesssys/marblerun/coordinator/store/distributed"
	"github.com/edgelesssys/marblerun/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

// Version is the Coordinator version.
var Version = "0.0.0" // Don't touch! Automatically injected at build-time.

// GitCommit is the git commit hash.
var GitCommit = "0000000000000000000000000000000000000000" // Don't touch! Automatically injected at build-time.

func run(log *zap.Logger, validator quote.Validator, issuer quote.Issuer, sealDir string, sealer seal.Sealer) {
	defer log.Sync() // flushes buffer, if any

	distributedDeployment := os.Getenv(constants.EnvDistributedDeployment) == "1" ||
		strings.Contains(strings.ToLower(os.Getenv(constants.EnvFeatureGates)), "distributedcoordinator") // for backward compatibility

	log.Info("Starting coordinator", zap.String("version", Version), zap.String("commit", GitCommit), zap.Bool("distributed", distributedDeployment))

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

	backend := os.Getenv(constants.EnvStoreBackend)
	if !distributedDeployment {
		backend = "default"
	}
	store, keyDistributor := setUpStore(backend, sealer, sealDir, validator, issuer, log)
	distributedStore, _ := store.(*dstore.Store)

	rec := recovery.NewMultiPartyRecovery(distributedStore, log)

	// creating core
	log.Info("Creating the Core object")
	co, err := core.NewCore(dnsNames, validator, issuer, store, rec, log, promFactoryPtr, eventlog)
	if err != nil {
		if _, ok := err.(core.QuoteError); !ok || !isDevMode() {
			log.Fatal("Cannot create Coordinator core", zap.Error(err))
		}
	}

	// Add quote generator to store so instances regenerate their quotes depending on loaded state
	if distributedStore != nil {
		distributedStore.SetQuoteGenerator(co)
	}
	clientAPI, err := clientapi.New(store, rec, co, keyDistributor, log)
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
		if _, err := clientAPI.SetManifest(context.Background(), content); err != nil {
			log.Fatal("Cannot set startup manifest", zap.Error(err))
		}
	}

	// start client server
	log.Info("Starting the client server")
	mux := server.CreateServeMux(clientAPI, promFactoryPtr, log)
	clientServerTLSConfig, err := co.GetTLSConfig()
	if err != nil {
		log.Fatal("Cannot create TLS credentials", zap.Error(err))
	}
	go server.RunClientServer(mux, clientServerAddr, clientServerTLSConfig, log)

	// start key distributor
	keyDistributor.Start()

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

func isDevMode() bool {
	return util.Getenv(constants.DevMode, constants.DevModeDefault) == "1"
}

func setUpStore(backend string, sealer seal.Sealer, sealDir string, qv quote.Validator, qi quote.Issuer, log *zap.Logger) (store.Store, keyDistributor) {
	var store store.Store
	var keyDistributor keyDistributor

	switch backend {
	case constants.StoreBackendKubernetes:
		// Load Kubernetes configuration from environment variables
		stateName := os.Getenv(constants.EnvK8sStateName)
		keyServiceName := os.Getenv(constants.EnvK8sKeyServiceName)
		kekMapName := os.Getenv(constants.EnvK8sKEKMapName)
		namespace := os.Getenv(constants.EnvK8sDeploymentNamespace)

		log.Info(
			"Setting up distributed Kubernetes store",
			zap.String("stateSecret", stateName),
			zap.String("keyAPIService", keyServiceName),
			zap.String("kekConfigMap", kekMapName),
			zap.String("namespace", namespace),
		)

		// Wrap sealer for distributed store
		sealer, err := dseal.New(sealer, kekMapName, namespace, log)
		if err != nil {
			log.Fatal("Failed setting up sealer", zap.Error(err))
		}

		// Create distributed store
		distributedStore, err := dstore.New(sealer, stateName, namespace, log)
		if err != nil {
			log.Fatal("Failed setting up store backend", zap.Error(err))
		}
		store = distributedStore

		// Get SGX instance properties
		var instanceProperties quote.PackageProperties
		if isSimulationMode() {
			log.Info("Running in simulation mode")
		} else {
			log.Info("Getting remote report for this instance to determine instance properties and TCB status")
			reportBytes, err := enclave.GetRemoteReport([]byte{0})
			if err != nil {
				log.Fatal("Failed to get remote report", zap.Error(err))
			}
			selfReport, err := enclave.VerifyRemoteReport(reportBytes)
			if err != nil && !errors.Is(err, attestation.ErrTCBLevelInvalid) {
				log.Fatal("Failed to verify remote report", zap.Error(err))
			}
			productID := binary.LittleEndian.Uint64(selfReport.ProductID)
			log.Info(
				"Got remote report for this instance",
				zap.Uint("securityVersion", selfReport.SecurityVersion),
				zap.Bool("debug", selfReport.Debug),
				zap.String("uniqueID", hex.EncodeToString(selfReport.UniqueID)),
				zap.String("signerID", hex.EncodeToString(selfReport.SignerID)),
				zap.Uint64("productID", productID),
				zap.String("tcbStatus", selfReport.TCBStatus.String()),
			)
			instanceProperties = quote.PackageProperties{
				Debug:               selfReport.Debug,
				UniqueID:            hex.EncodeToString(selfReport.UniqueID),
				SignerID:            hex.EncodeToString(selfReport.SignerID),
				ProductID:           &productID,
				SecurityVersion:     &selfReport.SecurityVersion,
				AcceptedTCBStatuses: []string{selfReport.TCBStatus.String()},
			}
		}

		// Set up key sharing
		keyClient, err := keyclient.New(instanceProperties, qi, log)
		if err != nil {
			log.Fatal("Failed setting up key client", zap.Error(err))
		}

		keyServer := keyserver.New(instanceProperties, qv, distributedStore, log)

		keyDistributor = distributor.New(keyServiceName, namespace, sealer, keyClient, keyServer, store, log)
	default:
		if err := os.MkdirAll(sealDir, 0o700); err != nil {
			log.Fatal("Cannot create or access sealdir. Please check the permissions for the specified path.", zap.Error(err))
		}
		var err error
		store, keyDistributor, err = newDefaultStore(sealer, sealDir, log)
		if err != nil {
			log.Fatal("Failed creating default store", zap.Error(err))
		}
	}

	return store, keyDistributor
}

func isSimulationMode() bool {
	id, err := enclave.GetSealKeyID()
	if err != nil {
		return false
	}
	return bytes.Equal(id, make([]byte, 16))
}

type keyDistributor interface {
	StartSharing(context.Context) error
	Start()
}
