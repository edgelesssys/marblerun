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

// Context keys known to the Coordinator
type ctxKey int

const (
	clientTLSCert ctxKey = iota
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
	// TODO: produce shorter lived certificates
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
		return nil, errors.New("node doesn't have a cert or quote yet")
	}
	return c.quote, nil
}

// Activate activates a node (implements the CoordinatorNodeServer interface)
func (c *Core) Activate(ctx context.Context, req *rpc.ActivationReq) (*rpc.ActivationResp, error) {
	defer c.mux.Unlock()
	if err := c.requireState(acceptingNodes); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "cannot accept nodes in current state")
	}

	node, nodeExists := c.manifest.Nodes[req.GetNodeType()]
	if !nodeExists {
		return nil, status.Error(codes.InvalidArgument, "unknown node type requested")
	}

	// get the node's TLS cert (used in this connection) and check corresponding quote
	tlsCert := getclientTLSCert(ctx)
	if tlsCert == nil {
		return nil, status.Error(codes.Unauthenticated, "couldn't get node TLS certificate")
	}
	pkg, pkgExists := c.manifest.Packages[node.Package]
	if !pkgExists {
		return nil, status.Error(codes.Internal, "undefined package")
	}
	infraMatch := false
	for _, infra := range c.manifest.Infrastructures {
		if c.qv.Validate(req.GetQuote(), tlsCert, pkg, infra) == nil {
			infraMatch = true
			break
		}
	}
	if !infraMatch {
		return nil, status.Error(codes.Unauthenticated, "invalid quote")
	}

	// check activation budget (MaxActivations == 0 means infinite budget)
	activations := c.activations[req.GetNodeType()]
	if node.MaxActivations > 0 && activations >= node.MaxActivations {
		return nil, status.Error(codes.ResourceExhausted, "reached max activations count for node type")
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
		IsCA:                  false,
	}
	certRaw, err := x509.CreateCertificate(rand.Reader, &template, c.cert, csr.PublicKey, c.privk)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to issue certificate")
	}

	// write response
	resp := &rpc.ActivationResp{
		Certificate: certRaw,
		Parameters:  &node.Parameters,
	}
	// TODO: scan files for certificate placeholders like "$$root_ca" and replace those
	c.activations[req.GetNodeType()]++
	return resp, nil
}

func getclientTLSCert(ctx context.Context) []byte {
	// TODO: we assume for now that the client TLS cert is available via the context. Need to figure out how exactly this works with gRPC and TLS.
	cert, ok := ctx.Value(clientTLSCert).([]byte)
	if ok {
		return cert
	}
	return nil
}
