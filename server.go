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
	"strconv"
	"sync"
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

const coordinatorName string = "Coordinator"

// Server implements the core of the Coordinator logic
type Server struct {
	cert        *x509.Certificate
	privk       ed25519.PrivateKey
	manifest    Manifest
	state       state
	qv          quote.Validator
	qc          quote.Creator
	activations map[string]uint
	mux         sync.Mutex
}

// Needs to be paired with `defer s.mux.Unlock()`
func (s *Server) requireState(state state) error {
	s.mux.Lock()
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

func generateSerial() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

func (s *Server) generateCert(orgName string) error {
	defer s.mux.Unlock()
	if err := s.requireState(uninitialized); err != nil {
		return err
	}

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
			CommonName:   "Coordinator",
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
	s.cert, err = x509.ParseCertificate(certRaw)
	if err != nil {
		return err
	}
	s.privk = privk
	s.advanceState()
	return nil
}

// SetManifest sets the manifest of the coordinator
func (s *Server) SetManifest(ctx context.Context, rawManifest []byte) error {
	defer s.mux.Unlock()
	if err := s.requireState(acceptingManifest); err != nil {
		return err
	}
	if err := json.Unmarshal(rawManifest, &s.manifest); err != nil {
		return err
	}
	s.advanceState()
	return nil
}

// Activate activates a node (implements the CoordinatorNodeServer interface)
func (s *Server) Activate(ctx context.Context, req *rpc.ActivationReq, connCert RawCert) (*rpc.ActivationResp, error) {
	defer s.mux.Unlock()
	if err := s.requireState(acceptingManifest); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "cannot accept nodes in current state")
	}

	node, nodeExists := s.manifest.Nodes[req.GetNodeType()]
	if !nodeExists {
		return nil, status.Error(codes.InvalidArgument, "unknown node type requested")
	}

	// check activation budget (MaxActivations == 0 means infinite budget)
	activations := s.activations[req.GetNodeType()]
	if node.MaxActivations > 0 && activations >= node.MaxActivations {
		return nil, status.Error(codes.ResourceExhausted, "reached max activations count for node type")
	}

	// check quote for certificate wrt to requested package
	pkg, pkgExists := s.manifest.Packages[node.Package]
	if !pkgExists {
		return nil, status.Error(codes.InvalidArgument, "unknown package requested")
	}
	if err := s.qv.Validate(req.GetQuote(), connCert, pkg); err != nil {
		return nil, status.Error(codes.Unauthenticated, "failed to validate quote")
	}

	// parse and verify CSR
	csr, err := x509.ParseCertificateRequest(req.GetCSR())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to parse CSR")
	}
	if csr.CheckSignature() != nil {
		return nil, status.Error(codes.InvalidArgument, "signature over CSR is invalid")
	}
	serialNumber, err := generateSerial()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate serial")
	}

	// create certificate
	// overwrite common name in CSR
	// TODO: do we actually need the CSR?
	csr.Subject.CommonName = req.GetNodeType() + strconv.FormatUint(uint64(activations), 10)
	notBefore := time.Now()
	notAfter := notBefore.Add(math.MaxInt64)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: false,
		IsCA:                  false,
	}
	certRaw, err := x509.CreateCertificate(rand.Reader, &template, s.cert, csr.PublicKey, s.privk)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to issue certificate")
	}

	// write response
	resp := &rpc.ActivationResp{
		Certificate: certRaw,
		Parameters:  &node.Parameters,
	}
	// TODO: scan files for certificate placeholders like "$$root_ca" and replace those
	s.activations[req.GetNodeType()]++
	return resp, nil
}
