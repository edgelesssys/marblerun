package util

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math"
	"math/big"
	"net"
	"time"

	"google.golang.org/grpc/credentials"
)

// GenerateMarbleCredentials returns dummy Marble TLS scredentials for testing
func GenerateMarbleCredentials() (certTLS *x509.Certificate, cert []byte, csr []byte, privk ed25519.PrivateKey, err error) {
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

// GenerateCert generates a new self-signed certificate associated key-pair
func GenerateCert() (*x509.Certificate, ed25519.PrivateKey, error) {

	// code (including generateSerial()) adapted from golang.org/src/crypto/tls/generate_cert.go
	pubk, privk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(math.MaxInt64)

	serialNumber, err := generateSerial()
	if err != nil {
		return nil, nil, err
	}

	// TODO: what else do we need to set here?
	// Do we need x509.KeyUsageKeyEncipherment?
	template := x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: false,
		IsCA:                  true,
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
func GenerateCSR(DNSNames []string, privk ed25519.PrivateKey) (*x509.CertificateRequest, error) {
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

// LoadTLSCredentials returns a TLS configuration based on cert and privk
func LoadTLSCredentials(cert *x509.Certificate, privk ed25519.PrivateKey) (credentials.TransportCredentials, error) {
	clientCert, err := getTLSCertificate(cert, privk)
	if err != nil {
		return nil, fmt.Errorf("failed to get Marble self-signed x509 certificate")
	}
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{*clientCert},
		InsecureSkipVerify: true,
	}
	return credentials.NewTLS(tlsConfig), nil
}

// getTLSCertificate creates a TLS certificate for the Marbles self-signed x509 certificate
func getTLSCertificate(cert *x509.Certificate, privk ed25519.PrivateKey) (*tls.Certificate, error) {
	return tlsCertFromDER(cert.Raw, privk), nil
}

func tlsCertFromDER(certDER []byte, privk interface{}) *tls.Certificate {
	return &tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: privk}
}
