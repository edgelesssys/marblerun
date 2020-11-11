// Copyright (c) Edgeless Systems GmbH.
// Licensed under the MIT License.

// Package premain contains the logic invoked before the applications actual main-function, that authenticates to the coordinator and pulls configurations and secrets which are subsequently passed to the application.
package premain

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"log"
	"net"
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

// storeUUID stores the uuid to the fs
func storeUUID(appFs afero.Fs, marbleUUID uuid.UUID, filename string) error {
	uuidBytes, err := marbleUUID.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal UUID: %v", err)
	}
	if err := afero.WriteFile(appFs, filename, uuidBytes, 0600); err != nil {
		return fmt.Errorf("failed to store uuid to file: %v", err)
	}
	return nil
}

// readUUID reads the uuid from the fs if present
func readUUID(appFs afero.Fs, filename string) (*uuid.UUID, error) {
	uuidBytes, err := afero.ReadFile(appFs, filename)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	marbleUUID := uuid.New()
	if err := marbleUUID.UnmarshalBinary(uuidBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal UUID: %v", err)
	}
	return &marbleUUID, nil
}

// getUUID loads or generates the uuid
func getUUID(appFs afero.Fs, uuidFile string) (uuid.UUID, error) {
	// check if we have a uuid stored in the fs (means we are restarted)
	log.Println("loading UUID")
	existingUUID, err := readUUID(appFs, uuidFile)
	if err != nil {
		return uuid.UUID{}, err
	}

	// generate new UUID if not present
	if existingUUID == nil {
		log.Println("UUID not found. Generating a new UUID")
		return uuid.New(), nil
	}

	log.Println("found UUID:", existingUUID.String())
	return *existingUUID, nil
}

func generateCertificate() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	marbleDNSNamesString := util.MustGetenv(config.DNSNames)
	marbleDNSNames := strings.Split(marbleDNSNamesString, ",")
	ipAddrs := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	return util.GenerateCert(marbleDNSNames, ipAddrs, false)
}

// PreMain runs before the App's actual main routine and authenticates with the Coordinator
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
	return preMain(ertvalidator.NewERTIssuer(), activateRPC, hostfs, enclavefs)
}

// PreMainMock mocks the quoting and file system handling in the PreMain routine for testing.
func PreMainMock() error {
	hostfs := afero.NewOsFs()
	return preMain(quote.NewFailIssuer(), activateRPC, hostfs, hostfs)
}

func preMain(issuer quote.Issuer, activate activateFunc, hostfs, enclavefs afero.Fs) error {
	prefixBackup := log.Prefix()
	defer log.SetPrefix(prefixBackup)
	log.SetPrefix("[PreMain] ")
	log.Println("starting PreMain")

	// get env variables
	log.Println("fetching env variables")
	coordAddr := util.MustGetenv(config.CoordinatorAddr)
	marbleType := util.MustGetenv(config.Type)
	marbleDNSNamesString := util.MustGetenv(config.DNSNames)
	marbleDNSNames := strings.Split(marbleDNSNamesString, ",")
	uuidFile := util.MustGetenv(config.UUIDFile)

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
		log.Println("failed to get quote. Proceeding in simulation mode")
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

	// store UUID to file
	log.Println("storing UUID")
	if err := storeUUID(hostfs, marbleUUID, uuidFile); err != nil {
		return err
	}

	if err := applyParameters(params, enclavefs); err != nil {
		return err
	}

	log.Println("done with PreMain")
	return nil
}

type activateFunc func(req *rpc.ActivationReq, coordAddr string, tlsCredentials credentials.TransportCredentials) (*rpc.Parameters, error)

func activateRPC(req *rpc.ActivationReq, coordAddr string, tlsCredentials credentials.TransportCredentials) (*rpc.Parameters, error) {
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
		if err := fs.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		if err := afero.WriteFile(fs, path, []byte(data), 0600); err != nil {
			return err
		}
	}

	// Set environment variables
	log.Println("setting env vars from manifest")
	for key, value := range params.Env {
		if err := os.Setenv(key, value); err != nil {
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
