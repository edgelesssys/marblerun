package core

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"log"
	"math"
	"time"

	"github.com/edgelesssys/coordinator/coordinator/rpc"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Activate activates a marble (implements the MarbleServer interface)
func (c *Core) Activate(ctx context.Context, req *rpc.ActivationReq) (*rpc.ActivationResp, error) {
	defer c.mux.Unlock()
	if err := c.requireState(acceptingMarbles); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "cannot accept marbles in current state")
	}

	// get the marble's TLS cert (used in this connection) and check corresponding quote
	tlsCert := getClientTLSCert(ctx)
	if tlsCert == nil {
		return nil, status.Error(codes.Unauthenticated, "couldn't get marble TLS certificate")
	}

	if err := c.verifyManifestRequirement(tlsCert, req.GetQuote(), req.GetMarbleType()); err != nil {
		return nil, err
	}
	uuidStr := req.GetUUID()
	marbleUUID, err := uuid.Parse(uuidStr)
	if err != nil {
		return nil, err
	}

	certRaw, err := c.generateCertFromCSR(req.GetCSR(), req.GetMarbleType(), marbleUUID.String())
	if err != nil {
		return nil, err
	}
	// TODO: AB#186 Derive sealing key and return it marble

	// write response
	marble := c.manifest.Marbles[req.GetMarbleType()] // existence has been checked in verifyManifestRequirement
	resp := &rpc.ActivationResp{
		Certificate: certRaw,
		RootCA:      c.cert.Raw,
		Parameters:  &marble.Parameters,
	}
	// TODO: scan files for certificate placeholders like "$$root_ca" and replace those
	log.Printf("Successfully activated new Marble of type '%v: %v'\n", req.GetMarbleType(), marbleUUID.String())
	c.activations[req.GetMarbleType()]++
	return resp, nil
}

// verifyManifestRequirement verifies marble attempting to register with respect to manifest
func (c *Core) verifyManifestRequirement(tlsCert *x509.Certificate, quote []byte, marbleType string) error {
	marble, marbleExists := c.manifest.Marbles[marbleType]
	if !marbleExists {
		return status.Error(codes.InvalidArgument, "unknown marble type requested")
	}

	pkg, pkgExists := c.manifest.Packages[marble.Package]
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
	activations := c.activations[marbleType]
	if marble.MaxActivations > 0 && activations >= marble.MaxActivations {
		return status.Error(codes.ResourceExhausted, "reached max activations count for marble type")
	}
	return nil
}

// generateCertFromCSR signs the CSR from marble attempting to register
func (c *Core) generateCertFromCSR(csrReq []byte, marbleType string, marbleUUID string) ([]byte, error) {
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
	csr.Subject.CommonName = marbleUUID
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
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
	}
	certRaw, err := x509.CreateCertificate(rand.Reader, &template, c.cert, csr.PublicKey, c.privk)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to issue certificate")
	}

	return certRaw, nil
}
