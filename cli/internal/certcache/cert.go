/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package certcache

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/cli/internal/pkcs11"
	"github.com/edgelesssys/marblerun/util"
	"github.com/spf13/afero"
	"github.com/spf13/pflag"
)

// SaveCoordinatorCachedCert saves the Coordinator's certificate to a cert cache.
func SaveCoordinatorCachedCert(flags *pflag.FlagSet, fs afero.Fs, root, intermediate *x509.Certificate) error {
	certName, err := flags.GetString("coordinator-cert")
	if err != nil {
		return err
	}
	return saveCert(file.New(certName, fs), root, intermediate)
}

// LoadCoordinatorCachedCert loads a cached Coordinator certificate.
func LoadCoordinatorCachedCert(flags *pflag.FlagSet, fs afero.Fs) (root, intermediate *x509.Certificate, err error) {
	// Skip loading the certificate if we're accepting insecure connections.
	if insecure, err := flags.GetBool("insecure"); err != nil {
		return nil, nil, err
	} else if insecure {
		return nil, nil, nil
	}
	certName, err := flags.GetString("coordinator-cert")
	if err != nil {
		return nil, nil, err
	}
	return loadCert(file.New(certName, fs))
}

// LoadClientCert parses the command line flags to load a TLS client certificate.
// The returned cancel function must be called only after the certificate is no longer needed.
func LoadClientCert(flags *pflag.FlagSet) (crt *tls.Certificate, cancel func() error, err error) {
	certFile, err := flags.GetString("cert")
	if err != nil {
		return nil, nil, err
	}
	keyFile, err := flags.GetString("key")
	if err != nil {
		return nil, nil, err
	}

	pkcs11ConfigFile, err := flags.GetString("pkcs11-config")
	if err != nil {
		return nil, nil, err
	}
	pkcs11KeyID, err := flags.GetString("pkcs11-key-id")
	if err != nil {
		return nil, nil, err
	}
	pkcs11KeyLabel, err := flags.GetString("pkcs11-key-label")
	if err != nil {
		return nil, nil, err
	}
	pkcs11CertID, err := flags.GetString("pkcs11-cert-id")
	if err != nil {
		return nil, nil, err
	}
	pkcs11CertLabel, err := flags.GetString("pkcs11-cert-label")
	if err != nil {
		return nil, nil, err
	}

	var clientCert tls.Certificate
	switch {
	case pkcs11ConfigFile != "":
		clientCert, cancel, err = pkcs11.LoadX509KeyPair(pkcs11ConfigFile, pkcs11KeyID, pkcs11KeyLabel, pkcs11CertID, pkcs11CertLabel)
	case certFile != "" && keyFile != "":
		clientCert, err = tls.LoadX509KeyPair(certFile, keyFile)
		cancel = func() error { return nil }
	default:
		err = errors.New("neither PKCS#11 nor file-based client certificate can be loaded with the provided flags")
	}

	return &clientCert, cancel, err
}

func saveCert(fh *file.Handler, root, intermediate *x509.Certificate) error {
	if root == nil || intermediate == nil {
		return errors.New("root and intermediate certificate must not be nil")
	}

	pemChain := append(
		pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: intermediate.Raw,
		}),
		pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: root.Raw,
		})...,
	)

	return fh.Write(pemChain, file.OptMkdirAll|file.OptOverwrite)
}

func loadCert(file *file.Handler) (root, intermediate *x509.Certificate, err error) {
	pemChain, err := file.Read()
	if err != nil {
		return nil, nil, err
	}

	return util.CoordinatorCertChainFromPEM(pemChain)
}
