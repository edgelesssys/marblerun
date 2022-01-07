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
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/hkdf"
	corev1 "k8s.io/api/core/v1"
)

const (
	IntelEpc       corev1.ResourceName = "sgx.intel.com/epc"
	IntelEnclave   corev1.ResourceName = "sgx.intel.com/enclave"
	IntelProvision corev1.ResourceName = "sgx.intel.com/provision"
	AzureEpc       corev1.ResourceName = "kubernetes.azure.com/sgx_epc_mem_in_MiB"
	AlibabaEpc     corev1.ResourceName = "alibabacloud.com/sgx_epc_MiB"
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

// GetEPCResorceLimit returns the amount of EPC to set for k8s deployments depending on the used sgx device plugin.
func GetEPCResourceLimit(resourceKey string) string {
	switch resourceKey {
	case AzureEpc.String():
		// azure device plugin expects epc in MiB
		return "10"
	case AlibabaEpc.String():
		// alibaba device plugin expects epc in MiB
		return "10"
	case IntelEpc.String():
		// intels device plugin expects epc as a k8s resource quantity
		return "10Mi"
	default:
		return "10"
	}
}
