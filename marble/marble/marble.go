package marble

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/quote/ertvalidator"
	"github.com/edgelesssys/coordinator/coordinator/rpc"
	"github.com/edgelesssys/coordinator/marble/config"
	"github.com/edgelesssys/coordinator/util"
	"github.com/google/uuid"
	"github.com/spf13/afero"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// loadTLSCreddentials builds a TLS config from the Authenticator's self-signed certificate and the Coordinator's RootCA
func loadTLSCredentials(cert *x509.Certificate, privk ed25519.PrivateKey) (credentials.TransportCredentials, error) {
	clientCert, err := getTLSCertificate(cert, privk)
	if err != nil {
		return nil, fmt.Errorf("failed to get Marble self-signed x509 certificate")
	}
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{*clientCert},
		InsecureSkipVerify: true,
	}
	return credentials.NewTLS(tlsConfig), nil
}

// getTLSCertificate creates a TLS certificate for the Marbles self-signed x509 certificate
func getTLSCertificate(cert *x509.Certificate, privk ed25519.PrivateKey) (*tls.Certificate, error) {
	return tlsCertFromDER(cert.Raw, privk), nil
}

// tlsCertFromDER converts a certificate from raw DER representation to a tls.Certificate
func tlsCertFromDER(certDER []byte, privk interface{}) *tls.Certificate {
	return &tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: privk}
}

// generateSerial returns a random serialNumber
func generateSerial() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// generateCert generates a new self-signed certificate associated key-pair
func generateCert() (*x509.Certificate, ed25519.PrivateKey, error) {

	// code (including generateSerial()) adapted from golang.org/src/crypto/tls/generate_cert.go
	pubk, privk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(math.MaxInt64)

	serialNumber, err := generateSerial()
	if err != nil {
		return nil, nil, err
	}

	// TODO: what else do we need to set here?
	// Do we need x509.KeyUsageKeyEncipherment?
	template := x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: false,
		IsCA:                  true,
	}

	certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, pubk, privk)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return nil, nil, err
	}
	return cert, privk, nil
}

func generateCSR(marbleDNSNames []string, privk ed25519.PrivateKey) (*x509.CertificateRequest, error) {
	template := x509.CertificateRequest{
		DNSNames:    marbleDNSNames,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, &template, privk)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrRaw)
	if err != nil {
		return nil, err
	}
	return csr, nil
}

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

// PreMain is supposed to run before the App's actual main and authenticate with the Coordinator
func PreMain() error {
	// generate certificate
	cert, privk, err := generateCert()
	if err != nil {
		return err
	}
	baseFs := afero.NewOsFs()
	appFs := afero.NewBasePathFs(baseFs, filepath.Join(filepath.FromSlash("/edg"), "hostfs"))
	_, err = preMain(cert, privk, ertvalidator.NewERTIssuer(), appFs)
	return err
}

// PreMainMock is similar to PreMain but mocks the quoting and file handler interfaces
func PreMainMock() error {
	// generate certificate
	cert, privk, err := generateCert()
	if err != nil {
		return err
	}
	appFs := afero.NewOsFs()
	_, err = preMain(cert, privk, quote.NewFailIssuer(), appFs)
	return err
}

func preMain(cert *x509.Certificate, privk ed25519.PrivateKey, issuer quote.Issuer, appFs afero.Fs) (*rpc.Parameters, error) {
	log.SetPrefix("[PreMain] ")
	log.Println("starting PreMain")
	// get env variables
	log.Println("fetching env variables")
	coordAddr := util.MustGetenv(config.EdgCoordinatorAddr)
	marbleType := util.MustGetenv(config.EdgMarbleType)
	marbleDNSNames := []string{}
	marbleDNSNamesString := util.MustGetenv(config.EdgMarbleDNSNames)
	marbleDNSNames = strings.Split(marbleDNSNamesString, ",")
	uuidFile := util.MustGetenv(config.EdgMarbleUUIDFile)

	// load TLS Credentials
	log.Println("loading TLS Credentials")
	tlsCredentials, err := loadTLSCredentials(cert, privk)
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
	csr, err := generateCSR(marbleDNSNames, privk)
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
		if err := appFs.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
			return nil, err
		}
		if err := afero.WriteFile(appFs, path, []byte(data), 0600); err != nil {
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
