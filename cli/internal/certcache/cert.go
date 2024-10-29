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
func LoadClientCert(flags *pflag.FlagSet) (*tls.Certificate, error) {
	certFile, err := flags.GetString("cert")
	if err != nil {
		return nil, err
	}
	keyFile, err := flags.GetString("key")
	if err != nil {
		return nil, err
	}
	clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	return &clientCert, nil
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
