//go:generate protoc --proto_path=./ --go_out=plugins=grpc:./ --go_opt=paths=source_relative rpc/coordinator.proto

package coordinator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/rpc"
)

// Core implements the core logic of the Coordinator
type Core struct {
	cert        *x509.Certificate
	quote       []byte
	privk       ed25519.PrivateKey
	manifest    Manifest
	state       state
	qv          quote.Validator
	qi          quote.Issuer
	activations map[string]uint
	mux         sync.Mutex
}

// The sequence of states a Coordinator may be in
type state int

const (
	uninitialized state = iota
	acceptingManifest
	acceptingNodes
	closed
)

const coordinatorName string = "Coordinator"

// Needs to be paired with `defer c.mux.Unlock()`
func (c *Core) requireState(state state) error {
	c.mux.Lock()
	if c.state != state {
		return errors.New("server is not in expected state")
	}
	return nil
}

func (c *Core) advanceState() {
	c.state++
}

// NewCore creates and initializes a new Core object
func NewCore(orgName string, qv quote.Validator, qi quote.Issuer) (*Core, error) {
	c := &Core{
		state:       uninitialized,
		activations: make(map[string]uint),
		qv:          qv,
		qi:          qi,
	}
	if err := c.generateCert(orgName); err != nil {
		return nil, err
	}
	return c, nil
}

// SetManifest implements the CoordinatorClient
func (c *Core) SetManifest(ctx context.Context, rawManifest []byte) error {
	defer c.mux.Unlock()
	if err := c.requireState(acceptingManifest); err != nil {
		return err
	}
	if err := json.Unmarshal(rawManifest, &c.manifest); err != nil {
		return err
	}
	// TODO: sanitize manifest
	c.advanceState()
	return nil
}

// GetQuote gets the quote of the server
func (c *Core) GetQuote(ctx context.Context) ([]byte, error) {
	if c.state == uninitialized {
		return nil, errors.New("don't have a cert or quote yet")
	}
	return c.quote, nil
}

// Activate activates a node (implements the CoordinatorNodeServer interface)
func (c *Core) Activate(ctx context.Context, req *rpc.ActivationReq) (*rpc.ActivationResp, error) {
	defer c.mux.Unlock()
	if err := c.requireState(acceptingNodes); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "cannot accept nodes in current state")
	}

	tlsCert := getClientTLSCert(ctx)
	// get the node's TLS cert (used in this connection) and check corresponding quote
	if tlsCert == nil {
		return nil, status.Error(codes.Unauthenticated, "couldn't get node TLS certificate")
	}

	if err := c.verifyManifestRequirement(tlsCert, req.GetQuote(), req.GetNodeType()); err != nil {
		return nil, err
	}

	//TODO verifyQuote

	certRaw, err := c.generateCertFromCSR(req.GetCSR(), req.GetNodeType())

	if err != nil {
		return nil, err
	}
	// write response
	node, _ := c.manifest.Nodes[req.GetNodeType()]
	resp := &rpc.ActivationResp{
		Certificate: certRaw,
		Parameters:  &node.Parameters,
	}
	// TODO: scan files for certificate placeholders like "$$root_ca" and replace those
	c.activations[req.GetNodeType()]++
	return resp, nil
}

// verifyManifestRequirement verifies node attempting to register with respect to manifest
func (c *Core) verifyManifestRequirement(tlsCert *x509.Certificate, quote []byte, nodeType string) error {
	node, nodeExists := c.manifest.Nodes[nodeType]
	if !nodeExists {
		return status.Error(codes.InvalidArgument, "unknown node type requested")
	}

	pkg, pkgExists := c.manifest.Packages[node.Package]
	if !pkgExists {
		return status.Error(codes.Internal, "undefined package")
	}
	infraMatch := false
	for _, infra := range c.manifest.Infrastructures {
		if c.qv.Validate(quote, tlsCert.Raw, pkg, infra) == nil {
			infraMatch = true
			break
		}
	}
	if !infraMatch {
		return status.Error(codes.Unauthenticated, "invalid quote")
	}

	// check activation budget (MaxActivations == 0 means infinite budget)
	activations := c.activations[nodeType]
	if node.MaxActivations > 0 && activations >= node.MaxActivations {
		return status.Error(codes.ResourceExhausted, "reached max activations count for node type")
	}

	return nil
}

// generateCertFromCSR signs the CSR from node attempting to register
func (c *Core) generateCertFromCSR(csrReq []byte, nodeType string) ([]byte, error) {
	// parse and verify CSR
	csr, err := x509.ParseCertificateRequest(csrReq)
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
	csr.Subject.CommonName = nodeType + strconv.FormatUint(uint64(c.activations[nodeType]), 10)
	notBefore := time.Now()
	// TODO: produce shorter lived certificates
	notAfter := notBefore.Add(math.MaxInt64)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: false,
		IsCA: false,
	}
	certRaw, err := x509.CreateCertificate(rand.Reader, &template, c.cert, csr.PublicKey, c.privk)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to issue certificate")
	}

	return certRaw, nil
}

// GetTLSCertificate creates a TLS certificate for the Coordinators self-signed x509 certificate
func (c *Core) GetTLSCertificate() (*tls.Certificate, error) {
	if c.state == uninitialized {
		return nil, errors.New("don't have a cert yet")
	}
	return tlsCertFromDER(c.cert.Raw, c.privk), nil
}

func generateSerial() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

func (c *Core) generateCert(orgName string) error {
	defer c.mux.Unlock()
	if err := c.requireState(uninitialized); err != nil {
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
			CommonName:   coordinatorName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: false,
		IsCA: true,
	}

	certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, pubk, privk)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return err
	}
	quote, err := c.qi.Issue(certRaw)
	if err != nil {
		return err
	}
	c.cert = cert
	c.quote = quote
	c.privk = privk
	c.advanceState()
	return nil
}

func getClientTLSCert(ctx context.Context) *x509.Certificate {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}
	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	// the following check is just for safety (not for security)
	if !ok {
		return nil
	}
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil
	}
	return tlsInfo.State.PeerCertificates[0]
}

func tlsCertFromDER(certDER []byte, privk interface{}) *tls.Certificate {
	return &tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: privk}
}
