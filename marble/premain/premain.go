// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package premain contains the logic invoked before the applications actual main-function, that authenticates to the coordinator and pulls configurations and secrets which are subsequently passed to the application.
package premain

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/quote/ertvalidator"
	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"github.com/edgelesssys/marblerun/marble/config"
	"github.com/edgelesssys/marblerun/util"
	"github.com/google/uuid"
	"github.com/spf13/afero"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// storeUUID stores the uuid to the fs.
func storeUUID(appFs afero.Fs, marbleUUID uuid.UUID, filename string) error {
	uuidBytes, err := marbleUUID.MarshalText()
	if err != nil {
		return fmt.Errorf("failed to marshal UUID: %v", err)
	}
	if err := afero.WriteFile(appFs, filename, uuidBytes, 0o600); err != nil {
		return fmt.Errorf("failed to store uuid to file: %v", err)
	}
	return nil
}

// readUUID reads the uuid from the fs if present.
func readUUID(appFs afero.Fs, filename string) (*uuid.UUID, error) {
	uuidBytes, err := afero.ReadFile(appFs, filename)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	marbleUUID := uuid.New()
	if err := marbleUUID.UnmarshalText(uuidBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal UUID: %v", err)
	}

	return &marbleUUID, nil
}

// getUUID loads or generates the uuid.
func getUUID(appFs afero.Fs, uuidFile string) (uuid.UUID, error) {
	// check if we have a uuid stored in the fs (means we are restarted or it was set by the admission controller)
	log.Println("loading UUID")
	existingUUID, err := readUUID(appFs, uuidFile)
	if err != nil {
		return uuid.UUID{}, err
	}

	// generate new UUID if not present and store it
	if existingUUID == nil {
		log.Println("UUID not found. Generating and storing a new UUID")
		newUUID := uuid.New()
		if err := storeUUID(appFs, newUUID, uuidFile); err != nil {
			return uuid.UUID{}, err
		}
		return newUUID, nil
	}

	log.Println("found UUID:", existingUUID.String())
	return *existingUUID, nil
}

func generateCertificate() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	marbleDNSNamesString := util.Getenv(config.DNSNames, config.DNSNamesDefault)
	marbleDNSNames := strings.Split(marbleDNSNamesString, ",")
	ipAddrs := util.DefaultCertificateIPAddresses
	return util.GenerateCert(marbleDNSNames, ipAddrs, false)
}

// PreMain runs before the App's actual main routine and authenticates with the Coordinator.
//
// It obtains a quote from the CPU and authenticates itself to the Coordinator through remote attestation.
// After successful authentication PreMain will set the files, environment variables and commandline arguments according to the manifest.
// Finally it will mount the host file system under '/edg/hostfs' before returning execution to the actual application.
func PreMain() error {
	hostfs := afero.NewBasePathFs(afero.NewOsFs(), filepath.Join(filepath.FromSlash("/edg"), "hostfs"))
	if err := syscall.Mount("/", "/", "edg_memfs", 0, ""); err != nil {
		return err
	}
	enclavefs := afero.NewOsFs()
	return PreMainEx(ertvalidator.NewERTIssuer(), ActivateRPC, hostfs, enclavefs)
}

// PreMainEgo works similar to PreMain, but let's EGo's premain handle the in-enclave memory filesystem mounting.
//
//nolint:revive
func PreMainEgo() error {
	hostfs := afero.NewBasePathFs(afero.NewOsFs(), filepath.Join(filepath.FromSlash("/edg"), "hostfs"))
	enclavefs := afero.NewOsFs()
	return PreMainEx(ertvalidator.NewERTIssuer(), ActivateRPC, hostfs, enclavefs)
}

// PreMainMock mocks the quoting and file system handling in the PreMain routine for testing.
//
//nolint:revive
func PreMainMock() error {
	hostfs := afero.NewOsFs()
	return PreMainEx(quote.NewFailIssuer(), ActivateRPC, hostfs, hostfs)
}

// PreMainEx is like PreMain, but allows to customize the quoting and file system handling.
//
//nolint:revive
func PreMainEx(issuer quote.Issuer, activate ActivateFunc, hostfs, enclavefs afero.Fs) error {
	prefixBackup := log.Prefix()
	defer log.SetPrefix(prefixBackup)
	log.SetPrefix("[PreMain] ")
	log.Println("starting PreMain")

	// get env variables
	log.Println("fetching env variables")
	coordAddr := util.Getenv(config.CoordinatorAddr, config.CoordinatorAddrDefault)
	marbleType := util.MustGetenv(config.Type)
	marbleDNSNamesString := util.Getenv(config.DNSNames, config.DNSNamesDefault)
	marbleDNSNames := strings.Split(marbleDNSNamesString, ",")
	uuidFile := util.Getenv(config.UUIDFile, config.UUIDFileDefault())

	cert, privk, err := generateCertificate()
	if err != nil {
		return err
	}

	// Load TLS Credentials with InsecureSkipVerify enabled. (The coordinator verifies the marble, but not the other way round.)
	log.Println("loading TLS Credentials")
	tlsCredentials, err := util.LoadGRPCTLSCredentials(cert, privk, true)
	if err != nil {
		return err
	}

	// load or generate UUID
	marbleUUID, err := getUUID(hostfs, uuidFile)
	if err != nil {
		return err
	}

	// generate CSR
	log.Println("generating CSR")
	csr, err := util.GenerateCSR(marbleDNSNames, privk)
	if err != nil {
		return err
	}

	// generate Quote
	log.Println("generating quote")
	if issuer == nil {
		// default
		issuer = ertvalidator.NewERTIssuer()
	}
	quote, err := issuer.Issue(cert.Raw)
	if err != nil {
		log.Printf("failed to get quote: %v. Proceeding in simulation mode", err)
		// If we run in SimulationMode we get an error here
		// For testing purpose we do not want to just fail here
		// Instead we store an empty quote that will only be accepted if the coordinator also runs in SimulationMode
		quote = []byte{}
	}

	// authenticate with Coordinator
	req := &rpc.ActivationReq{
		CSR:        csr.Raw,
		MarbleType: marbleType,
		Quote:      quote,
		UUID:       marbleUUID.String(),
	}
	log.Println("activating marble of type", marbleType)
	params, err := activate(req, coordAddr, tlsCredentials)
	if err != nil {
		return err
	}

	if err := applyParameters(params, enclavefs); err != nil {
		return err
	}

	log.Println("done with PreMain")
	return nil
}

// ActivateFunc is called by premain to activate the Marble and get its parameters.
type ActivateFunc func(req *rpc.ActivationReq, coordAddr string, tlsCredentials credentials.TransportCredentials) (*rpc.Parameters, error)

// ActivateRPC sends an activation request to the Coordinator.
func ActivateRPC(req *rpc.ActivationReq, coordAddr string, tlsCredentials credentials.TransportCredentials) (*rpc.Parameters, error) {
	connection, err := grpc.Dial(coordAddr, grpc.WithTransportCredentials(tlsCredentials))
	if err != nil {
		return nil, err
	}
	defer connection.Close()

	client := rpc.NewMarbleClient(connection)
	activationResp, err := client.Activate(context.Background(), req)
	if err != nil {
		return nil, err
	}

	return activationResp.GetParameters(), nil
}

func applyParameters(params *rpc.Parameters, fs afero.Fs) error {
	// Store files in file system
	log.Println("creating files from manifest")
	for path, data := range params.Files {
		if err := fs.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := afero.WriteFile(fs, path, data, 0o600); err != nil {
			return err
		}
	}

	// Set environment variables
	log.Println("setting env vars from manifest")
	for key, value := range params.Env {
		if err := os.Setenv(key, string(value)); err != nil {
			return err
		}
	}

	// Set Args
	if len(params.Argv) > 0 {
		os.Args = params.Argv
	} else {
		os.Args = []string{"./marble"}
	}

	return nil
}
