//go:build !enclave

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package keyrelease

import "crypto/x509"

func initEnclave() error {
	var err error
	rootCerts, err = x509.SystemCertPool()
	return err
}
