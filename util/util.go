// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package util

import (
	"crypto/sha256"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/hkdf"
)

// DefaultCertificateIPAddresses defines a placeholder value used for automated x509 certificate generation
var DefaultCertificateIPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}

// DeriveKey derives a key from a secret.
func DeriveKey(secret, salt []byte) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, secret, salt, nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}
	return key, nil
}

// MustGetenv returns the environment variable `name` if it exists or panics otherwise
func MustGetenv(name string) string {
	value := os.Getenv(name)
	if len(value) == 0 {
		log.Fatalln("environment variable not set:", name)
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
