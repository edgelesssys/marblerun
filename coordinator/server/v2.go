// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package server

import (
	"encoding/base64"
	"fmt"
	"net/http"
)

type clientAPIServerV2 struct {
	api clientAPI
}

// quoteGet retrieves a remote attestation quote and certificates.
// By default, the Coordinator will return a pre-generated quote over the root certificate of the TLS connection.
// If a nonce is supplied as a query parameter, a new quote will be generated over sha256(root_cert || nonce).
func (s *clientAPIServerV2) quoteGet(w http.ResponseWriter, r *http.Request) {
	var nonce []byte
	if nonceB64 := r.URL.Query().Get("nonce"); nonceB64 != "" {
		var err error
		nonce, err = base64.URLEncoding.DecodeString(nonceB64)
		if err != nil {
			writeJSONError(w, fmt.Sprintf("bad nonce format: %s", err), http.StatusBadRequest)
			return
		}
	}

	cert, quote, err := s.api.GetCertQuote(r.Context(), nonce)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, CertQuoteResp{cert, quote})
}
