//go:build enclave

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package keyrelease

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

var initOnce sync.Once

// initEnclave initializes the enclave by mounting CA certificates required for TLS with Azure services.
func initEnclave() error {
	var err error
	initOnce.Do(func() {
		const caFile = "/etc/ssl/certs/ca-certificates.crt"
		if err = unix.Mount(caFile, filepath.Join("/untrusted", caFile), "oe_host_file_system", 0, ""); err != nil {
			err = fmt.Errorf("mounting %s into enclave: %w", caFile, err)
			return
		}

		var caData []byte
		caData, err = os.ReadFile(filepath.Join("/untrusted", caFile))
		if err != nil {
			err = fmt.Errorf("reading CA certificates from %s: %w", caFile, err)
			return
		}
		rootCerts = x509.NewCertPool()
		rootCerts.AppendCertsFromPEM(caData)
	})
	return err
}
