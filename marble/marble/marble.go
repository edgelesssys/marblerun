package marble

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/quote/ertvalidator"
	"github.com/edgelesssys/coordinator/coordinator/rpc"
	"github.com/edgelesssys/coordinator/marble/config"
	"github.com/edgelesssys/coordinator/util"
	"github.com/google/uuid"
	"github.com/spf13/afero"
	"google.golang.org/grpc"
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

func genCert() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// generate certificate
	marbleDNSNamesString := util.MustGetenv(config.EdgMarbleDNSNames)
	marbleDNSNames := strings.Split(marbleDNSNamesString, ",")
	ipAddrs := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	return util.GenerateCert(marbleDNSNames, ipAddrs, false)
}

// PreMain is supposed to run before the App's actual main and authenticate with the Coordinator
func PreMain() error {
	cert, privk, err := genCert()
	if err != nil {
		return err
	}
	appFs := afero.NewBasePathFs(afero.NewOsFs(), filepath.Join(filepath.FromSlash("/edg"), "hostfs"))
	if err := syscall.Mount("/", "/", "edg_memfs", 0, ""); err != nil {
		return err
	}
	_, err = preMain(cert, privk, ertvalidator.NewERTIssuer(), appFs)
	return err
}

// PreMainMock is similar to PreMain but mocks the quoting and file handler interfaces
func PreMainMock() error {
	// generate certificate
	cert, privk, err := genCert()
	if err != nil {
		return err
	}
	appFs := afero.NewOsFs()
	_, err = preMain(cert, privk, quote.NewFailIssuer(), appFs)
	return err
}

func preMain(cert *x509.Certificate, privk *ecdsa.PrivateKey, issuer quote.Issuer, appFs afero.Fs) (*rpc.Parameters, error) {
	log.SetPrefix("[PreMain] ")
	log.Println("starting PreMain")
	// get env variables
	log.Println("fetching env variables")
	coordAddr := util.MustGetenv(config.EdgCoordinatorAddr)
	marbleType := util.MustGetenv(config.EdgMarbleType)
	marbleDNSNamesString := util.MustGetenv(config.EdgMarbleDNSNames)
	marbleDNSNames := strings.Split(marbleDNSNamesString, ",")
	uuidFile := util.MustGetenv(config.EdgMarbleUUIDFile)

	// load TLS Credentials
	log.Println("loading TLS Credentials")
	tlsCredentials, err := util.LoadTLSCredentials(cert, privk)
	if err != nil {
		return nil, err
	}

	// check if we have a uuid stored in the fs (means we are restarted)
	log.Println("loading UUID")
	existingUUID, err := readUUID(appFs, uuidFile)
	if err != nil {
		return nil, err
	}
	// generate new UUID if not present
	var marbleUUID uuid.UUID
	if existingUUID == nil {
		log.Println("UUID not found. Generating a new UUID")
		marbleUUID = uuid.New()
	} else {
		marbleUUID = *existingUUID
		log.Println("found UUID:", marbleUUID.String())
	}
	uuidStr := marbleUUID.String()

	// generate CSR
	log.Println("generating CSR")
	csr, err := util.GenerateCSR(marbleDNSNames, privk)
	if err != nil {
		return nil, err
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

	// initiate grpc connection to Coordinator
	cc, err := grpc.Dial(coordAddr, grpc.WithTransportCredentials(tlsCredentials))

	if err != nil {
		return nil, err
	}
	defer cc.Close()

	// authenticate with Coordinator
	req := &rpc.ActivationReq{
		CSR:        csr.Raw,
		MarbleType: marbleType,
		Quote:      quote,
		UUID:       uuidStr,
	}
	c := rpc.NewMarbleClient(cc)
	log.Println("activating marble of type", marbleType)
	activationResp, err := c.Activate(context.Background(), req)
	if err != nil {
		return nil, err
	}

	// store UUID to file
	log.Println("storing UUID")
	if err := storeUUID(appFs, marbleUUID, uuidFile); err != nil {
		return nil, err
	}

	// get params
	params := activationResp.GetParameters()

	// Store files in file system
	log.Println("creating files from manifest")
	for path, data := range params.Files {
		// edg_memfs does not support creating directories yet
		// if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		// 	return nil, err
		// }
		if err := ioutil.WriteFile(path, []byte(data), 0600); err != nil {
			return nil, err
		}
	}

	// Set environment variables
	log.Println("setting env vars from manifest")
	for key, value := range params.Env {
		if err := os.Setenv(key, value); err != nil {
			return nil, err
		}
	}

	// Set Args
	os.Args = params.Argv

	log.Println("done with PreMain")
	return params, nil
}
