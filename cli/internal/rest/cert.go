// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package rest

import (
	"crypto/tls"
	"encoding/pem"

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/spf13/afero"
	"github.com/spf13/pflag"
)

// SaveCoordinatorCachedCert saves the Coordinator's certificate to a cert cache.
func SaveCoordinatorCachedCert(flags *pflag.FlagSet, fs afero.Fs, caCert []*pem.Block) error {
	certName, err := flags.GetString("coordinator-cert")
	if err != nil {
		return err
	}
	return saveCert(file.New(certName, fs), caCert)
}

// LoadCoordinatorCachedCert loads a cached Coordinator certificate.
func LoadCoordinatorCachedCert(flags *pflag.FlagSet, fs afero.Fs) (caCert []*pem.Block, err error) {
	// Skip loading the certificate if we're accepting insecure connections.
	if insecure, err := flags.GetBool("insecure"); err != nil {
		return nil, err
	} else if insecure {
		return nil, nil
	}
	certName, err := flags.GetString("coordinator-cert")
	if err != nil {
		return nil, err
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

func saveCert(fh *file.Handler, caCert []*pem.Block) error {
	var pemCert []byte
	for _, block := range caCert {
		pemCert = append(pemCert, pem.EncodeToMemory(block)...)
	}

	return fh.Write(pemCert, file.OptMkdirAll|file.OptOverwrite)
}

func loadCert(file *file.Handler) ([]*pem.Block, error) {
	pemCert, err := file.Read()
	if err != nil {
		return nil, err
	}

	var caCert []*pem.Block
	for {
		var block *pem.Block
		block, pemCert = pem.Decode(pemCert)
		if block == nil {
			break
		}
		caCert = append(caCert, block)
	}
	return caCert, nil
}
