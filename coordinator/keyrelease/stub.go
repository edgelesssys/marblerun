//go:build !enclave

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package keyrelease

import (
	"crypto/x509"
	"os"
	"strings"

	"github.com/edgelesssys/marblerun/coordinator/constants"
)

func initEnclave() error {
	var err error
	rootCerts, err = x509.SystemCertPool()
	if err != nil {
		return err
	}
	return os.Setenv(strings.TrimPrefix(constants.EnvAzureFederatedTokenFile, "EDG_"), os.Getenv(constants.EnvAzureFederatedTokenFile))
}
