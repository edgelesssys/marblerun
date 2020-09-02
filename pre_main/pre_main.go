package premain

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"os"
	"time"

	"github.com/edgelesssys/coordinator/coordinator/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Required env variable with Coordinator addr
const edgCoordinatorAddr string = "EDG_COORDINATOR_ADDR"

// Unique ID of this marble
const edgMarbleID string = "EDG_MARBLE_ID"

// TLS Cert orgName
const orgName string = "Marble"

// File location of the Coordinators RootCA
const rootCAFile string = "/certs/root.pem"

// Authenticator holds the information for authenticating with the Coordinator
type Authenticator struct {
	commonName string
	privk      ed25519.PrivateKey
	pubk       ed25519.PublicKey
	tlsCert    *x509.Certificate
	quote      []byte
	signedCert *tls.Certificate
	params     *rpc.Parameters
}

// newAuthenticator creates a new Authenticator instance
func newAuthenticator(orgName string, commonName string) (*Authenticator, error) {
	a := &Authenticator{
		commonName: commonName,
	}
	if err := a.generateCert(orgName); err != nil {
		return nil, err
	}
	return a, nil
}

// loadTLSCreddentials builds a TLS config from the Authenticator's self-signed certificate and the Coordinator's RootCA
func loadTLSCredentials(a *Authenticator) (credentials.TransportCredentials, error) {
	pemCoordinatorCa, err := ioutil.ReadFile(rootCAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read rootCA file at %v", rootCAFile)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemCoordinatorCa) {
		return nil, fmt.Errorf("failed to add Coordinator CA's certificate")
	}
	clientCert, err := a.getTLSCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get Marble self-signed x509 certificate")
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*clientCert},
		RootCAs:      certPool,
	}
	return credentials.NewTLS(tlsConfig), nil
}

// getTLSCertificate creates a TLS certificate for the Marbles self-signed x509 certificate
func (a *Authenticator) getTLSCertificate() (*tls.Certificate, error) {
	return tlsCertFromDER(a.tlsCert.Raw, a.privk), nil
}

// generateSerial returns a random serialNumber
func generateSerial() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// generateCert generates a new self-signed certificate associated key-pair
func (a *Authenticator) generateCert(orgName string) error {

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
			Organization: []string{orgName},
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
	a.pubk = pubk
	a.privk = privk
	a.tlsCert = cert
	return nil
}

// tlsCertFromDER converts a certificate from raw DER representation to a tls.Certificate
func tlsCertFromDER(certDER []byte, privk interface{}) *tls.Certificate {
	return &tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: privk}
}

// preMain is supposed to run before the App's actual main and authenticate with the Coordinator
func preMain() {
	// get env variables
	coordAddr := os.Getenv(edgCoordinatorAddr)
	if len(coordAddr) == 0 {
		log.Fatalf("%v: Environment Variable not set.", edgCoordinatorAddr)
		return
	}
	marbleID := os.Getenv(edgMarbleID)
	if len(marbleID) == 0 {
		log.Fatalf("%v: Environment Variable not set.", edgMarbleID)
		return
	}

	// load TLS Credentials
	commonName := fmt.Sprintf("Marble_%v", marbleID)
	a, err := newAuthenticator(orgName, commonName)
	if err != nil {
		log.Fatalln("cannot create Authenticator: ", err)
	}
	tlsCredentials, err := loadTLSCredentials(a)
	if err != nil {
		log.Fatalln("cannot load TLS credentials: ", err)
	}

	// Initiate grpc connection to Coordinator
	cc, err := grpc.Dial(edgCoordinatorAddr, grpc.WithTransportCredentials(tlsCredentials))

	if err != nil {
		log.Fatalf("Could not connect: %v", err)
		return
	}

	defer cc.Close()

	// Authenticate with Coordinator
	c := rpc.NewPodClient(cc)
	req := &rpc.ActivationReq{
		CSR:     []byte("TODO"),
		PodType: "TODO",
		Quote:   []byte("TODO"),
	}

	activiationResp, err := c.Activate(context.Background(), req)
	if err != nil {
		log.Fatalf("Unexpected error %v", err)
	}
	a.signedCert = tlsCertFromDER(activiationResp.GetCertificate(), a.privk)
	a.params = activiationResp.GetParameters()

	// TODO: Store certificate in virtual file system and call actual main with params

}

func main() {
	preMain()
}
