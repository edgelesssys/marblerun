/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package util //nolint:revive

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

const marbleName string = "MarbleRun Marble"

// MustGenerateTestMarbleCredentials returns dummy Marble TLS credentials for testing.
func MustGenerateTestMarbleCredentials() (cert *x509.Certificate, csrRaw []byte, privk *ecdsa.PrivateKey) {
	dnsNames := []string{"localhost", "*.foobar.net", "*.example.org"}
	ipAddrs := DefaultCertificateIPAddresses

	cert, privk, err := GenerateCert(dnsNames, ipAddrs, false)
	if err != nil {
		panic(err)
	}

	csr, err := GenerateCSR(dnsNames, privk)
	if err != nil {
		panic(err)
	}
	csrRaw = csr.Raw
	return cert, csrRaw, privk
}

// GenerateCert generates a new self-signed certificate associated key-pair.
func GenerateCert(subjAltNames []string, ipAddrs []net.IP, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	privk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(math.MaxInt64)

	serialNumber, err := GenerateCertificateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	additionalIPs, dnsNames := ExtractIPsFromAltNames(subjAltNames)

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: marbleName,
		},
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
		IPAddresses:  append(additionalIPs, ipAddrs...),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, &privk.PublicKey, privk)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return nil, nil, err
	}
	return cert, privk, nil
}

// GenerateCSR generates a new CSR for the given DNSNames and private key.
func GenerateCSR(subjAltNames []string, privk *ecdsa.PrivateKey) (*x509.CertificateRequest, error) {
	additionalIPs, dnsNames := ExtractIPsFromAltNames(subjAltNames)

	template := x509.CertificateRequest{
		DNSNames:    dnsNames,
		IPAddresses: append(DefaultCertificateIPAddresses, additionalIPs...),
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

// GenerateCertificateSerialNumber generates a random serial number for an X.509 certificate.
func GenerateCertificateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// LoadGRPCTLSCredentials returns a TLS configuration based on cert and privk.
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

// ExtractIPsFromAltNames extracts IP addresses and DNS names from a list of subject alternative names.
func ExtractIPsFromAltNames(subjAltNames []string) ([]net.IP, []string) {
	var dnsNames []string
	var additionalIPs []net.IP
	for _, name := range subjAltNames {
		if ip := net.ParseIP(name); ip != nil {
			additionalIPs = append(additionalIPs, ip)
		} else {
			dnsNames = append(dnsNames, name)
		}
	}
	return additionalIPs, dnsNames
}
