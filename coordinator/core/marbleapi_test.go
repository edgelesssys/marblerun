package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math"
	"net"
	"testing"
	"time"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/rpc"
	"github.com/edgelesssys/coordinator/test"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestMarbleAPI(t *testing.T) {
	assert := assert.New(t)

	// parse manifest
	var manifest Manifest
	err := json.Unmarshal([]byte(test.ManifestJSON), &manifest)
	assert.Nil(err)

	// create core
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := NewMockSealer()
	coreServer, err := NewCore("edgeless", []string{"localhost"}, validator, issuer, sealer)
	assert.NotNil(coreServer)
	assert.Nil(err)

	spawner := marbleSpawner{
		assert:    assert,
		issuer:    issuer,
		validator: validator,
		manifest:  manifest,
	}

	// try to activate first backend marble prematurely before manifest is set
	spawner.newMarble(coreServer, "backend_first", "Azure", false)

	// set manifest
	assert.Nil(coreServer.SetManifest(context.TODO(), []byte(test.ManifestJSON)))

	// activate first backend
	spawner.newMarble(coreServer, "backend_first", "Azure", true)

	// try to activate another first backend
	spawner.newMarble(coreServer, "backend_first", "Azure", false)

	// activate 10 other backend
	pickInfra := func(i int) string {
		if i&1 == 0 {
			return "Azure"
		} else {
			return "Alibaba"
		}
	}
	for i := 0; i < 10; i++ {
		spawner.newMarble(coreServer, "backend_other", pickInfra(i), true)
	}

	// activate 10 frontend
	for i := 0; i < 10; i++ {
		spawner.newMarble(coreServer, "frontend", pickInfra(i), true)
	}
}

type marbleSpawner struct {
	manifest   Manifest
	validator  *quote.MockValidator
	issuer     quote.Issuer
	serverAddr string
	assert     *assert.Assertions
}

func (ms marbleSpawner) newMarble(coreServer *Core, marbleType string, infraName string, shouldSucceed bool) {
	// create certificate and CSR
	certTLS, cert, csr, err := generateMarbleCredentials()
	ms.assert.Nil(err)
	ms.assert.NotNil(cert)
	ms.assert.NotNil(csr)

	// create mock quote using values from the manifest
	quote, err := ms.issuer.Issue(cert)
	ms.assert.NotNil(quote)
	ms.assert.Nil(err)
	marble, ok := ms.manifest.Marbles[marbleType]
	ms.assert.True(ok)
	pkg, ok := ms.manifest.Packages[marble.Package]
	ms.assert.True(ok)
	infra, ok := ms.manifest.Infrastructures[infraName]
	ms.assert.True(ok)
	ms.validator.AddValidQuote(quote, cert, pkg, infra)

	tlsInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{certTLS},
		},
	}

	ctx := peer.NewContext(context.TODO(), &peer.Peer{
		AuthInfo: tlsInfo,
	})

	resp, err := coreServer.Activate(ctx, &rpc.ActivationReq{
		CSR:        csr,
		MarbleType: marbleType,
		Quote:      quote,
		UUID:       uuid.New().String(),
	})

	if !shouldSucceed {
		ms.assert.NotNil(err)
		ms.assert.Nil(resp)
		return
	}
	ms.assert.Nil(err, "Activate failed: %v", err)
	ms.assert.NotNil(resp)

	// Validate response
	params := resp.GetParameters()
	// Validate Files
	if marble.Parameters.Files != nil {
		ms.assert.Equal(marble.Parameters.Files, params.Files)
	}
	// Validate Argv
	if marble.Parameters.Argv != nil {
		ms.assert.Equal(marble.Parameters.Argv, params.Argv)
	}

	// Validate SealKey
	pemSealKey := resp.GetParameters().Env["SEAL_KEY"]
	ms.assert.NotNil(pemSealKey)
	p, _ := pem.Decode([]byte(pemSealKey))
	ms.assert.NotNil(p)

	// Validate Marble Key
	pemMarbleKey := resp.GetParameters().Env["MARBLE_KEY"]
	ms.assert.NotNil(pemMarbleKey)
	p, _ = pem.Decode([]byte(pemMarbleKey))
	ms.assert.NotNil(p)

	// Validate Cert
	pemCert := resp.GetParameters().Env["MARBLE_CERT"]
	ms.assert.NotNil(pemCert)
	p, _ = pem.Decode([]byte(pemCert))
	ms.assert.NotNil(p)
	newCert, err := x509.ParseCertificate(p.Bytes)
	ms.assert.Nil(err)
	ms.assert.Equal(coordinatorName, newCert.Issuer.CommonName)
	// Check CommonName
	_, err = uuid.Parse(newCert.Subject.CommonName)
	ms.assert.Nil(err, "cert.Subject.CommonName is not a valid UUID: %v", err)
	// Check KeyUusage:
	ms.assert.Equal(certTLS.KeyUsage, newCert.KeyUsage)
	// Check ExtKeyUsage
	ms.assert.Equal(certTLS.ExtKeyUsage, newCert.ExtKeyUsage)
	// Check DNSNames
	ms.assert.Equal(certTLS.DNSNames, newCert.DNSNames)
	ms.assert.Equal(certTLS.IPAddresses, newCert.IPAddresses)
	// Check Signature
	pubk := coreServer.cert.PublicKey.(ed25519.PublicKey)
	ms.assert.True(ed25519.Verify(pubk, newCert.RawTBSCertificate, newCert.Signature))
	// Check cert-chain
	pemRootCA := resp.GetParameters().Env["ROOT_CA"]
	ms.assert.NotNil(pemRootCA)
	p, _ = pem.Decode([]byte(pemRootCA))
	ms.assert.NotNil(p)
	rootCA, err := x509.ParseCertificate(p.Bytes)
	ms.assert.Nil(err, "cannot parse rootCA: %v", err)
	roots := x509.NewCertPool()
	roots.AddCert(rootCA)
	opts := x509.VerifyOptions{
		Roots:         roots,
		CurrentTime:   time.Now(),
		DNSName:       "localhost",
		Intermediates: x509.NewCertPool(),
		KeyUsages:     newCert.ExtKeyUsage,
	}
	_, err = newCert.Verify(opts)
	ms.assert.Nil(err, "failed to verify new certificate: %v", err)

}

func generateMarbleCredentials() (certTLS *x509.Certificate, cert []byte, csr []byte, err error) {
	const orgName string = "Edgeless Systems GmbH"
	pubk, privk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	// create self-signed certificate for use in initial TLS connection
	notBefore := time.Now()
	notAfter := notBefore.Add(math.MaxInt64)

	serialNumber, err := generateSerial()
	if err != nil {
		return
	}
	templateCert := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{orgName},
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		DNSNames:    []string{"localhost", "*.foobar.net", "*.example.org"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	cert, err = x509.CreateCertificate(rand.Reader, &templateCert, &templateCert, pubk, privk)
	if err != nil {
		return
	}

	certTLS, err = x509.ParseCertificate(cert)
	if err != nil {
		return
	}

	// create CSR
	templateCSR := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{orgName},
		},
		PublicKey:   pubk,
		DNSNames:    []string{"localhost", "*.foobar.net", "*.example.org"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	csr, err = x509.CreateCertificateRequest(rand.Reader, &templateCSR, privk)
	return
}
