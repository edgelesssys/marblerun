package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math"
	"math/big"
	"net"
	"time"

	"google.golang.org/grpc/credentials"
)

// OrgName is the Edgeless org name for cetificates
const OrgName string = "Edgeless Systems GmbH"

// GenerateMarbleCredentials returns dummy Marble TLS credentials for testing
func GenerateMarbleCredentials() (certTLS *x509.Certificate, certRaw []byte, csrRaw []byte, privk *ecdsa.PrivateKey, err error) {
	dnsNames := []string{"localhost", "*.foobar.net", "*.example.org"}
	ipAddrs := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}

	certTLS, privk, err = GenerateCert(dnsNames, ipAddrs, false)
	if err != nil {
		return
	}
	certRaw = certTLS.Raw

	csr, err := GenerateCSR(dnsNames, privk)
	csrRaw = csr.Raw
	return
}

// GenerateCert generates a new self-signed certificate associated key-pair
func GenerateCert(DNSNames []string, IPAddrs []net.IP, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// code (including generateSerial()) adapted from golang.org/src/crypto/tls/generate_cert.go
	privk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubk := &privk.PublicKey
	notBefore := time.Now()
	notAfter := notBefore.Add(math.MaxInt64)

	serialNumber, err := generateSerial()
	if err != nil {
		return nil, nil, err
	}

	// TODO: what else do we need to set here?
	// Do we need x509.KeyUsageKeyEncipherment?
	template := x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{OrgName},
		},
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     DNSNames,
		IPAddresses:  IPAddrs,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, pubk, privk)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return nil, nil, err
	}
	return cert, privk, nil
}

// GenerateCSR generates a new CSR for the given DNSNames and private key
func GenerateCSR(DNSNames []string, privk *ecdsa.PrivateKey) (*x509.CertificateRequest, error) {
	template := x509.CertificateRequest{
		DNSNames:    DNSNames,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, &template, privk)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrRaw)
	if err != nil {
		return nil, err
	}
	return csr, nil
}

func generateSerial() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// LoadGRPCTLSCredentials returns a TLS configuration based on cert and privk
func LoadGRPCTLSCredentials(cert *x509.Certificate, privk *ecdsa.PrivateKey, insecureSkipVerify bool) (credentials.TransportCredentials, error) {
	clientCert := TLSCertFromDER(cert.Raw, privk)
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{*clientCert},
		InsecureSkipVerify: insecureSkipVerify,
	}
	return credentials.NewTLS(tlsConfig), nil
}

// TLSCertFromDER converts a DER certificate to a TLS certificate.
func TLSCertFromDER(certDER []byte, privk interface{}) *tls.Certificate {
	return &tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: privk}
}
