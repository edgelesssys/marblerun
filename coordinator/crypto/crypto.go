// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// crypto provides common cryptographic functions used by the Coordinator.
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math"
	"time"

	"github.com/edgelesssys/marblerun/util"
)

// GenerateCert creates a new certificate with the given parameters.
// If privk is nil, a new private key is generated.
func GenerateCert(
	dnsNames []string, commonName string, privk *ecdsa.PrivateKey,
	parentCertificate *x509.Certificate, parentPrivateKey *ecdsa.PrivateKey,
) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// Generate private key
	var err error
	if privk == nil {
		privk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generating private key: %w", err)
		}
	}

	// Certificate parameters
	notBefore := time.Now()
	notAfter := notBefore.Add(math.MaxInt64)

	serialNumber, err := util.GenerateCertificateSerialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("generating serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:    dnsNames,
		IPAddresses: util.DefaultCertificateIPAddresses,
		NotBefore:   notBefore,
		NotAfter:    notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	if parentCertificate == nil {
		parentCertificate = &template
		parentPrivateKey = privk
	}
	certRaw, err := x509.CreateCertificate(rand.Reader, &template, parentCertificate, &privk.PublicKey, parentPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("creating certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing certificate: %w", err)
	}

	return cert, privk, nil
}
