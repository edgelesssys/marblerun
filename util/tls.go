// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
	return
}

// GenerateCert generates a new self-signed certificate associated key-pair.
func GenerateCert(dnsNames []string, ipAddrs []net.IP, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	privk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(math.MaxInt64)

	serialNumber, err := GenerateCertificateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	// TODO: what else do we need to set here?
	// Do we need x509.KeyUsageKeyEncipherment?
	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: marbleName,
		},
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
		IPAddresses:  ipAddrs,

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
func GenerateCSR(dnsNames []string, privk *ecdsa.PrivateKey) (*x509.CertificateRequest, error) {
	template := x509.CertificateRequest{
		DNSNames:    dnsNames,
		IPAddresses: DefaultCertificateIPAddresses,
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
