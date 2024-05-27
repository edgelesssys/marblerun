// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package premain

import (
	"crypto/sha256"
	"errors"
	"os"
	"strings"

	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"github.com/edgelesssys/marblerun/util"
	"google.golang.org/grpc/credentials"
)

// GramineActivate sends an activation request to the Coordinator and initializes protected files.
func GramineActivate(req *rpc.ActivationReq, coordAddr string, tlsCredentials credentials.TransportCredentials) (*rpc.Parameters, error) {
	// call the actual Activate function
	params, err := ActivateRPCNoTTLS(req, coordAddr, tlsCredentials)
	if err != nil {
		return nil, err
	}

	// Write encrypted file keys if present. We must do this "manually" here because premain will write files
	// in an unspecified order. However, the keys must be written before any other encrypted file is written.
	const atKeyBasePath = "/dev/attestation/keys/"
	for keyPath, key := range params.Files {
		if strings.HasPrefix(keyPath, atKeyBasePath) {
			if err := os.WriteFile(keyPath, key, 0); err != nil {
				return nil, err
			}
			delete(params.Files, keyPath)
		}
	}

	// Gramine v1.2 and older use a different key pseudo file system, add this here if present
	const pfKeyPath = "/dev/attestation/protected_files_key"
	if key, ok := params.Files[pfKeyPath]; ok {
		if err := os.WriteFile(pfKeyPath, key, 0); err != nil {
			return nil, err
		}
		delete(params.Files, pfKeyPath)
	}

	return params, nil
}

// GramineQuoteIssuer issues quotes.
type GramineQuoteIssuer struct{}

// Issue issues a quote for remote attestation for a given message (usually a certificate).
func (GramineQuoteIssuer) Issue(cert []byte) ([]byte, error) {
	hash := sha256.Sum256(cert)

	f, err := os.OpenFile("/dev/attestation/user_report_data", os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}

	_, err = f.Write(hash[:])
	f.Close()
	if err != nil {
		return nil, err
	}

	f, err = os.Open("/dev/attestation/quote")
	if err != nil {
		return nil, err
	}

	quote := make([]byte, 8192)
	quoteSize, err := f.Read(quote)
	f.Close()
	if err != nil {
		return nil, err
	}

	if !(0 < quoteSize && quoteSize < len(quote)) {
		return nil, errors.New("invalid quote size")
	}

	return util.AddOEQuoteHeader(quote[:quoteSize]), nil
}
