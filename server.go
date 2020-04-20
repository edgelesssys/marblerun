//go:generate protoc --proto_path=./ --go_out=plugins=grpc:./ --go_opt=paths=source_relative rpc/coordinator.proto

package coordinator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"time"

	"google.golang.org/grpc/codes"

	"google.golang.org/grpc/status"

	"edgeless.systems/mesh/coordinator/quote"
	"edgeless.systems/mesh/coordinator/rpc"
)

type state int

// The sequence of states a coordinator may be in
const (
	uninitialized state = iota
	acceptingManifest
	acceptingNodes
	closed
)

// Server implements the core of the Coordinator logic
type Server struct {
	cert        Cert
	privk       ed25519.PrivateKey
	manifest    Manifest
	state       state
	qv          quote.Validator
	qc          quote.Creator
	activations map[string]uint
}

func (s *Server) requireState(state state) error {
	if s.state != state {
		return errors.New("server is not in expected state")
	}
	return nil
}

func (s *Server) advanceState() {
	s.state++
}

// NewServer creates and initializes a new server object
func NewServer(orgName string) (*Server, error) {
	s := &Server{
		state:       uninitialized,
		activations: make(map[string]uint),
	}
	if err := s.generateCert(orgName); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) generateCert(orgName string) error {
	if err := s.requireState(uninitialized); err != nil {
		return err
	}

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

	s.cert, err = x509.CreateCertificate(rand.Reader, &template, &template, pubk, privk)
	if err != nil {
		return err
	}
	s.privk = privk
	s.advanceState()
	return nil
}

// SetManifest sets the manifest of the coordinator
func (s *Server) SetManifest(ctx context.Context, rawManifest []byte) error {
	if err := s.requireState(acceptingManifest); err != nil {
		return err
	}
	if err := json.Unmarshal(rawManifest, &s.manifest); err != nil {
		return err
	}
	s.advanceState()
	return nil
}

// ActivateNode activates a node (implements the CoordinatorNodeServer interface)
func (s *Server) Activate(ctx context.Context, req *rpc.ActivationReq, cert Cert) (*rpc.ActivationResp, error) {
	if err := s.requireState(acceptingManifest); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "cannot accept nodes in current state")
	}
	node, nodeExists := s.manifest.Nodes[req.GetNodeType()]
	// check activation budget (MaxActivations == 0 means infinite budget)
	if node.MaxActivations > 0 && s.activations[req.GetNodeType()] >= node.MaxActivations {
		return nil, status.Error(codes.ResourceExhausted, "reached max activations count for node type")
	}
	// check quote for certificate wrt to requested package
	pkg, pkgExists := s.manifest.Packages[node.Package]
	if !pkgExists {
		return nil, status.Error(codes.InvalidArgument, "unknown package requested")
	}
	if err := s.qv.Validate(req.GetQuote(), cert, pkg); err != nil {
		return nil, status.Error(codes.Unauthenticated, "failed to validate quote")
	}
	// parse CSR and issue certificate
	csr, err := x509.ParseCertificateRequest(req.GetCsr())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to parse CSR")
	}
	if csr.CheckSignature() != nil {
		return nil, status.Error(codes.InvalidArgument, "signature over CSR is invalid")
	}
	x509.CreateCertificate()

	s.activations[req.GetNodeType()]++
}
