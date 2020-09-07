package premain

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"time"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// edgCoordinatorAddr: Required env variable with Coordinator addr
const edgCoordinatorAddr string = "EDG_COORDINATOR_ADDR"

// edgMarbleType: Required env variable with type of this marble
const edgMarbleType string = "EDG_MARBLE_TYPE"

// TODO: Create a central place where all certificate information is managed
// TLS Cert orgName
const orgName string = "Edgeless Systems GmbH"

// Authenticator holds the information for authenticating with the Coordinator
type Authenticator struct {
	commonName string
	orgName    string
	privk      ed25519.PrivateKey
	pubk       ed25519.PublicKey
	initCert   *x509.Certificate
	csr        *x509.CertificateRequest
	quote      []byte
	qi         quote.Issuer
	marbleCert *x509.Certificate
	params     *rpc.Parameters
}

// NewAuthenticator creates a new Authenticator instance
func NewAuthenticator(orgName string, commonName string, qi quote.Issuer) (*Authenticator, error) {
	a := &Authenticator{
		commonName: commonName,
		orgName:    orgName,
		qi:         qi,
	}
	if err := a.generateCert(); err != nil {
		return nil, err
	}
	return a, nil
}

// loadTLSCreddentials builds a TLS config from the Authenticator's self-signed certificate and the Coordinator's RootCA
func loadTLSCredentials(a *Authenticator) (credentials.TransportCredentials, error) {
	clientCert, err := a.getTLSCertificate()
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
func (a *Authenticator) getTLSCertificate() (*tls.Certificate, error) {
	return tlsCertFromDER(a.initCert.Raw, a.privk), nil
}

// generateSerial returns a random serialNumber
func generateSerial() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// generateCert generates a new self-signed certificate associated key-pair
func (a *Authenticator) generateCert() error {

	// code (including generateSerial()) adapted from golang.org/src/crypto/tls/generate_cert.go
	pubk, privk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(math.MaxInt64)

	serialNumber, err := generateSerial()
	if err != nil {
		return err
	}

	// TODO: what else do we need to set here?
	// Do we need x509.KeyUsageKeyEncipherment?
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{a.orgName},
			CommonName:   a.commonName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: false,
		IsCA:                  true,
	}

	certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, pubk, privk)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return err
	}
	quote, err := a.qi.Issue(certRaw)
	if err != nil {
		return err
	}
	a.pubk = pubk
	a.privk = privk
	a.quote = quote
	a.initCert = cert
	return nil
}

func (a *Authenticator) generateCSR() error {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{a.orgName},
			CommonName:   a.commonName,
		},
		PublicKey: a.pubk,
	}
	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, &template, a.privk)
	if err != nil {
		return err
	}
	csr, err := x509.ParseCertificateRequest(csrRaw)
	if err != nil {
		return err
	}
	a.csr = csr
	return nil
}

// tlsCertFromDER converts a certificate from raw DER representation to a tls.Certificate
func tlsCertFromDER(certDER []byte, privk interface{}) *tls.Certificate {
	return &tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: privk}
}

// PreMain is supposed to run before the App's actual main and authenticate with the Coordinator
func PreMain(a *Authenticator) (*x509.Certificate, *rpc.Parameters, error) {
	// get env variables
	coordAddr := os.Getenv(edgCoordinatorAddr)
	if len(coordAddr) == 0 {
		return nil, nil, fmt.Errorf("environment variable not set: %v", edgCoordinatorAddr)
	}

	marbleType := os.Getenv(edgMarbleType)
	if len(marbleType) == 0 {
		return nil, nil, fmt.Errorf("environment variable not set: %v", edgMarbleType)
	}

	// load TLS Credentials
	tlsCredentials, err := loadTLSCredentials(a)
	if err != nil {
		return nil, nil, err
	}

	// initiate grpc connection to Coordinator
	cc, err := grpc.Dial(coordAddr, grpc.WithTransportCredentials(tlsCredentials))

	if err != nil {
		return nil, nil, err
	}

	defer cc.Close()

	// generate CSR
	if err := a.generateCSR(); err != nil {
		return nil, nil, err
	}

	// authenticate with Coordinator
	c := rpc.NewMarbleClient(cc)
	req := &rpc.ActivationReq{
		CSR:        a.csr.Raw,
		MarbleType: marbleType,
		Quote:      a.quote,
	}

	activiationResp, err := c.Activate(context.Background(), req)
	if err != nil {
		return nil, nil, err
	}
	newCert, err := x509.ParseCertificate(activiationResp.GetCertificate())
	if err != nil {
		return nil, nil, err
	}
	a.marbleCert = newCert
	a.params = activiationResp.GetParameters()

	// TODO: Store certificate in virtual file system and call actual main with params
	return a.marbleCert, a.params, nil

}

func main() {
	commonName := "marble"          // Coordinator will assign an ID to us
	issuer := quote.NewMockIssuer() // TODO: Use real issuer
	a, err := NewAuthenticator(orgName, commonName, issuer)
	if err != nil {
		log.Fatalf("failed to create Authenticator: %v", err)
	}
	_, _, err = PreMain(a)
	if err != nil {
		log.Fatalf("pre_main failed: %v", err)
	}
}
