// Copyright (c) Edgeless Systems GmbH.
// Licensed under the MIT License.

package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/edgelesssys/coordinator/coordinator/config"
	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/server"
	"github.com/edgelesssys/coordinator/util"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"go.uber.org/zap"
)

func run(validator quote.Validator, issuer quote.Issuer, sealKey []byte, sealDirPrefix string) {
	// Setup logging with Zap Logger
	// Development Logger shows a stacktrace for warnings & errors, Production Logger only for errors
	zapLogger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatal(err)
		return
	}
	defer zapLogger.Sync() // flushes buffer, if any

	// Make sure that log statements internal to gRPC library are logged using the zapLogger as well.
	grpc_zap.ReplaceGrpcLoggerV2(zapLogger)

	zapLogger.Info("starting coordinator")

	// fetching env vars
	sealDir := util.MustGetenv(config.SealDir)
	sealDir = filepath.Join(sealDirPrefix, sealDir)
	dnsNamesString := util.MustGetenv(config.DNSNames)
	dnsNames := strings.Split(dnsNamesString, ",")
	clientServerAddr := util.MustGetenv(config.ClientAddr)
	meshServerAddr := util.MustGetenv(config.MeshAddr)

	// creating core
	zapLogger.Info("creating the Core object")
	if err := os.MkdirAll(sealDir, 0700); err != nil {
		zapLogger.Fatal("Cannot create or access sealdir. Please check the permissions for the specified path.", zap.Error(err))
	}
	sealer := core.NewAESGCMSealer(sealDir, sealKey)
	core, err := core.NewCore(dnsNames, validator, issuer, sealer, zapLogger)
	if err != nil {
		panic(err)
	}

	// start client server
	zapLogger.Info("starting the client server")
	mux := server.CreateServeMux(core)
	clientServerTLSConfig, err := core.GetTLSConfig()
	if err != nil {
		panic(err)
	}
	go server.RunClientServer(mux, clientServerAddr, clientServerTLSConfig, zapLogger)

	// run marble server
	zapLogger.Info("starting the marble server")
	addrChan := make(chan string)
	errChan := make(chan error)
	go server.RunMarbleServer(core, meshServerAddr, addrChan, errChan, zapLogger)
	for {
		select {
		case err := <-errChan:
			if err != nil {
				panic(err)
			}
			return
		case grpcAddr := <-addrChan:
			zapLogger.Info("started gRPC server", zap.String("grpcAddr", grpcAddr))
		}
	}
}
