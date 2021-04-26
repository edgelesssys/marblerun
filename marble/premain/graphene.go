// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package premain

import (
	"crypto/sha256"
	"errors"
	"io/ioutil"
	"os"

	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"google.golang.org/grpc/credentials"
)

// GrapheneActivate sends an activation request to the Coordinator and initializes protected files.
func GrapheneActivate(req *rpc.ActivationReq, coordAddr string, tlsCredentials credentials.TransportCredentials) (*rpc.Parameters, error) {
	// call the actual Activate function
	params, err := ActivateRPC(req, coordAddr, tlsCredentials)
	if err != nil {
		return nil, err
	}

	// Write the protected files key if present. We must do this "manually" here because premain will write files
	// in an unspecified order. However, the key must be written before any other protected file is written.
	const pfKeyPath = "/dev/attestation/protected_files_key"
	if key, ok := params.Files[pfKeyPath]; ok {
		if err := ioutil.WriteFile(pfKeyPath, []byte(key), 0); err != nil {
			return nil, err
		}
	}

	return params, nil
}

// GrapheneQuoteIssuer issues quotes
type GrapheneQuoteIssuer struct{}

// Issue issues a quote for remote attestation for a given message (usually a certificate)
func (GrapheneQuoteIssuer) Issue(cert []byte) ([]byte, error) {
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

	return prependOEHeaderToRawQuote(quote[:quoteSize]), nil
}
