// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"

	"golang.org/x/crypto/hkdf"
)

// DefaultCertificateIPAddresses defines a placeholder value used for automated x509 certificate generation.
var DefaultCertificateIPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}

// DeriveKey derives a key from a secret.
func DeriveKey(secret, salt []byte, length uint) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, secret, salt, nil)
	key := make([]byte, length)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}
	return key, nil
}

// MustGetenv returns the environment variable `name` if it exists or panics otherwise.
func MustGetenv(name string) string {
	value := os.Getenv(name)
	if len(value) == 0 {
		log.Fatalln("environment variable not set:", name)
	}
	return value
}

// Getenv returns the environment variable `name` if it exists or the handed fallback value elsewise.
func Getenv(name string, fallback string) string {
	value := os.Getenv(name)
	if len(value) == 0 {
		return fallback
	}
	return value
}

// MustGetLocalListenerAndAddr returns a TCP listener on a system-chosen port on localhost and its address.
func MustGetLocalListenerAndAddr() (net.Listener, string) {
	const localhost = "localhost:"

	listener, err := net.Listen("tcp", localhost)
	if err != nil {
		panic(err)
	}

	addr := listener.Addr().String()

	// addr contains IP address, we want hostname
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	return listener, localhost + port
}

// XORBytes XORs two byte slices.
func XORBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("lengths of byte slices differ: %v != %v", len(a), len(b))
	}
	result := make([]byte, len(a))
	for i := range result {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}

// EncryptOAEP is a wrapper function for rsa.EncryptOAEP for a nicer syntax.
func EncryptOAEP(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
}

// DecryptOAEP is a wrapper function for rsa.DecryptOAEP for a nicer syntax.
func DecryptOAEP(priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, nil)
}

// MustGetwd returns the current working directory and panics if it cannot be dcetermined.
func MustGetwd() string {
	// If MarbleRun runs in an enclave, EDG_CWD should be set.
	wd := os.Getenv("EDG_CWD")
	if len(wd) != 0 {
		return wd
	}
	// If MarbleRun runs outside an enclave, try to find the working directory.
	wd, err := os.Getwd()
	if err == nil {
		return wd
	}
	panic(err)
}

// CoordinatorCertChainFromPEM parses a Coordinator's PEM encoded certificate chain into x509.Certificate objects.
func CoordinatorCertChainFromPEM(pemChain []byte) (rootCert, intermediateCert *x509.Certificate, err error) {
	intermediatePEM, rest := pem.Decode(pemChain)
	if intermediatePEM == nil {
		return nil, nil, errors.New("could not parse Coordinator intermediate certificate from PEM data")
	}
	rootPEM, _ := pem.Decode(rest)
	if rootPEM == nil {
		return nil, nil, errors.New("could not parse Coordinator root certificate from PEM data")
	}
	intermediateCert, err = x509.ParseCertificate(intermediatePEM.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing Coordinator intermediate certificate: %w", err)
	}
	rootCert, err = x509.ParseCertificate(rootPEM.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing Coordinator root certificate: %w", err)
	}

	return rootCert, intermediateCert, nil
}

// AddOEQuoteHeader adds an OpenEnclave quote header to the given quote.
// If the quote already has a header, this is a no-op.
func AddOEQuoteHeader(quote []byte) []byte {
	quoteHeader := make([]byte, 16)
	binary.LittleEndian.PutUint32(quoteHeader, 1)     // version
	binary.LittleEndian.PutUint32(quoteHeader[4:], 2) // OE_REPORT_TYPE_SGX_REMOTE
	binary.LittleEndian.PutUint64(quoteHeader[8:], uint64(len(quote)))

	// If the quote already has a header, return it as is.
	if len(quote) > 8 && slices.Equal(quoteHeader[:8], quote[:8]) {
		return quote
	}
	return append(quoteHeader, quote...)
}
