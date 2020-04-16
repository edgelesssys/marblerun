package coordinator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math"
	"math/big"
	"time"

	"edgeless.systems/mesh/coordinator/rpc"
)

// Server implements the core of the Coordinator logic
type Server struct {
	Cert  []byte
	privk ed25519.PrivateKey
}

// NewServer creates and initializes a new server object
func NewServer(orgName string) (*Server, error) {
	s := &Server{}
	if err := s.generateCert(orgName); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) generateCert(orgName string) error {
	// code adapted from golang.org/src/crypto/tls/generate_cert.go
	pubk, privk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(math.MaxInt64)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	// TODO: what else do we need to set here?
	// Do we need x509.KeyUsageKeyEncipherment?
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{orgName},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, pubk, privk)
	if err != nil {
		return err
	}
	s.Cert = cert
	s.privk = privk
	return nil
}

// ActivateNode implements the CoordinatorServer interface (protobuf)
func (s *Server) ActivateNode(context.Context, *rpc.ActivationReq) (*rpc.ActivationRepl, error) {
	return nil, errors.New("not implemented")
}
