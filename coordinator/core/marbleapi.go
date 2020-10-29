package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"math"
	"strings"
	"time"

	"github.com/edgelesssys/coordinator/coordinator/rpc"
	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Activate implements the MarbleAPI function to authenticate a marble (implements the MarbleServer interface)
//
// Verifies the marble's integritiy and subsequently provides the marble with a certificate for authentication and application-specific parameters as defined in the Coordinator's manifest.
//
// req needs to contain a MarbleType present in the Coordinator's manifest and a CSR with the Subject and DNSNames set with desired values.
//
// Returns a signed certificate-key-pair and the application's parameters if the authentication was successful.
// Returns an error if the authenitcation failed.
func (c *Core) Activate(ctx context.Context, req *rpc.ActivationReq) (*rpc.ActivationResp, error) {
	log.Println("activation request for type", req.MarbleType)
	defer c.mux.Unlock()
	if err := c.requireState(stateAcceptingMarbles); err != nil {
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
	// generate key-pair for marble
	privk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pubk := privk.PublicKey
	encodedPrivKey, err := x509.MarshalPKCS8PrivateKey(privk)
	if err != nil {
		return nil, err
	}

	// Derive sealing key using HKDF and return it to marble
	uuidBytes, err := marbleUUID.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// Derive key
	hkdf := hkdf.New(sha256.New, uuidBytes, c.privk.D.Bytes(), nil)
	sealKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, sealKey); err != nil {
		return nil, err
	}

	certRaw, err := c.generateCertFromCSR(req.GetCSR(), pubk, req.GetMarbleType(), marbleUUID.String())
	if err != nil {
		return nil, err
	}

	pemRootCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
	pemMarbleCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certRaw})
	pemMarbleKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPrivKey})
	pemSealKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: sealKey})
	marble := c.manifest.Marbles[req.GetMarbleType()] // existence has been checked in verifyManifestRequirement
	params := customizeParameters(marble.Parameters, pemRootCA, pemMarbleCert, pemMarbleKey, pemSealKey)

	// write response
	resp := &rpc.ActivationResp{
		Parameters: params,
	}

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
	if !c.InSimulationMode() {
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
	}

	// check activation budget (MaxActivations == 0 means infinite budget)
	activations := c.activations[marbleType]
	if marble.MaxActivations > 0 && activations >= marble.MaxActivations {
		return status.Error(codes.ResourceExhausted, "reached max activations count for marble type")
	}
	return nil
}

// generateCertFromCSR signs the CSR from marble attempting to register
func (c *Core) generateCertFromCSR(csrReq []byte, pubk ecdsa.PublicKey, marbleType string, marbleUUID string) ([]byte, error) {
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
	csr.Subject.Organization = c.cert.Issuer.Organization
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
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
	}
	certRaw, err := x509.CreateCertificate(rand.Reader, &template, c.cert, &pubk, c.privk)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to issue certificate")
	}

	return certRaw, nil
}

// customizeParameters replaces the placeholders in the manifest's parameters with the actual values
func customizeParameters(params *rpc.Parameters, rootCA []byte, marbleCert []byte, marbleKey []byte, sealKey []byte) *rpc.Parameters {
	customParams := rpc.Parameters{
		Argv:  params.Argv,
		Files: make(map[string]string),
		Env:   make(map[string]string),
	}
	// replace placeholders in files
	r := strings.NewReplacer(rootCAPlaceholder, string(rootCA),
		marbleCertPlaceholder, string(marbleCert),
		marbleKeyPlaceholder, string(marbleKey),
		sealKeyPlaceholder, string(sealKey))
	for path, data := range params.Files {
		newData := r.Replace(data)
		customParams.Files[path] = newData
	}

	for name, data := range params.Env {
		newData := r.Replace(data)
		customParams.Env[name] = newData
	}

	return &customParams
}
