// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/edgelesssys/marblerun/coordinator/clientapi"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
)

// clientAPIServerV2 serves the /api/v2 endpoints of the Coordinator.
// This API follows the JSend specification.
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
			writeJSONFailure(w, nil, fmt.Sprintf("bad nonce format: %s", err), http.StatusBadRequest)
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
		writeJSONFailure(w, nil, err.Error(), http.StatusBadRequest)
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

// signQuotePost receives an SGX quote and returns a signed quote.
// The Coordinator will verify the quote and sign it together with the TCB status of the quote using the root ECDSA key.
func (s *clientAPIServerV2) signQuotePost(w http.ResponseWriter, r *http.Request) {
	// Check if the current manifest allows signing quotes
	if !s.api.FeatureEnabled(r.Context(), manifest.FeatureSignQuoteEndpoint) {
		writeJSONError(w, "sign-quote endpoint is not enabled", http.StatusForbidden)
	}

	var req QuoteSignReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONFailure(w, nil, fmt.Sprintf("bad request: %s", err), http.StatusBadRequest)
		return
	}

	signature, tcbStatus, err := s.api.SignQuote(r.Context(), req.SGXQuote)
	if err != nil {
		var verifyErr *clientapi.QuoteVerifyError
		if errors.As(err, &verifyErr) {
			writeJSONFailure(w, nil, verifyErr.Error(), http.StatusBadRequest)
			return
		}

		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, QuoteSignResp{
		VerificationSignature: signature,
		TCBStatus:             tcbStatus,
	})
}

// writeJSONFailure writes a JSend failure response to the client.
// nolint:unparam
func writeJSONFailure(w http.ResponseWriter, v interface{}, message string, httpErrorCode int) {
	w.Header().Set("Content-Type", "application/json")
	dataToReturn := GeneralResponse{Status: "fail", Data: v, Message: message}
	w.WriteHeader(httpErrorCode)
	if err := json.NewEncoder(w).Encode(dataToReturn); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
