// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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

// recoverPost performs recovery of the Coordinator enclave when unsealing of the existing state fails.
// This API endpoint is only available when the coordinator is in recovery mode.
func (s *clientAPIServerV2) recoverPost(w http.ResponseWriter, r *http.Request) {
	var req RecoveryV2Request
	if err := json.NewDecoder(io.LimitReader(r.Body, 2048)).Decode(&req); err != nil {
		writeJSONFailure(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Perform recover and receive amount of remaining secrets (for multi-party recovery)
	remaining, err := s.api.Recover(r.Context(), req.RecoverySecret)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Construct status message based on remaining keys
	var statusMessage string
	if remaining != 0 {
		statusMessage = fmt.Sprintf("Secret was processed successfully. Upload the next secret. Remaining secrets: %d", remaining)
	} else {
		statusMessage = "Recovery successful."
	}

	writeJSON(w, RecoveryV2Resp{
		Remaining: remaining,
		Message:   statusMessage,
	})
}

// writeJSONFailure wires a JSend failure response to the client.
func writeJSONFailure(w http.ResponseWriter, v interface{}, httpErrorCode int) {
	w.Header().Set("Content-Type", "application/json")
	dataToReturn := GeneralResponse{Status: "fail", Data: v}
	w.WriteHeader(httpErrorCode)
	if err := json.NewEncoder(w).Encode(dataToReturn); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
