// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package v2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/edgelesssys/marblerun/coordinator/clientapi"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/server/handler"
)

// ClientAPIServer serves the Coordinator's v2 REST API.
type ClientAPIServer struct {
	api handler.ClientAPI
}

// NewServer creates a new ClientAPIServer.
func NewServer(api handler.ClientAPI) *ClientAPIServer {
	return &ClientAPIServer{api: api}
}

// ManifestGet retrieves the effective manifest of the Coordinator.
// Along the manifest, this endpoint also returns the manifest fingerprint (the hex encoded SHA-256 hash of the manifest),
// as well as an ASN.1 encoded ECDSA signature of the manifest signed by the root ECDSA key.
func (s *ClientAPIServer) ManifestGet(w http.ResponseWriter, r *http.Request) {
	signatureRootECDSA, manifest, err := s.api.GetManifestSignature(r.Context())
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fingerprint := sha256.Sum256(manifest)
	handler.WriteJSON(w, ManifestGetResponse{
		ManifestSignatureRootECDSA: signatureRootECDSA,
		ManifestFingerprint:        hex.EncodeToString(fingerprint[:]),
		Manifest:                   manifest,
	})
}

// ManifestPost sets the manifest of the Coordinator.
// If the manifest contains recovery data, the Coordinator will return the encrypted secrets to be used for recovery.
func (s *ClientAPIServer) ManifestPost(w http.ResponseWriter, r *http.Request) {
	var req ManifestSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.WriteJSONFailure(w, nil, err.Error(), http.StatusBadRequest)
		return
	}
	recoverySecretMap, err := s.api.SetManifest(r.Context(), req.Manifest)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// If recovery data is set, return it
	handler.WriteJSON(w, ManifestSetResponse{RecoverySecrets: recoverySecretMap})
}

// MonotonicCounterPost increments a monotonic counter of the Coordinator.
// The requesting Marble must be authorized to increment the counter.
func (s *ClientAPIServer) MonotonicCounterPost(w http.ResponseWriter, r *http.Request) {
	// Check if the current manifest allows this feature
	if !s.api.FeatureEnabled(r.Context(), manifest.FeatureMonotonicCounter) {
		handler.WriteJSONError(w, "MonotonicCounter feature is not enabled in the manifest", http.StatusForbidden)
		return
	}

	marbleType, marbleUUID, err := handler.VerifyMarble(s.api.VerifyMarble, r)
	if err != nil {
		handler.WriteJSONFailure(w, nil, err.Error(), http.StatusUnauthorized)
		return
	}

	var req MonotonicCounterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.WriteJSONFailure(w, nil, err.Error(), http.StatusBadRequest)
		return
	}

	value, err := s.api.SetMonotonicCounter(r.Context(), marbleType, marbleUUID, req.Name, req.Value)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	handler.WriteJSON(w, MonotonicCounterResponse{Value: value})
}

// QuoteGet retrieves a remote attestation quote and certificates.
// By default, the Coordinator will return a pre-generated quote over the root certificate of the TLS connection.
// If a nonce is supplied as a query parameter, a new quote will be generated over sha256(root_cert || nonce).
func (s *ClientAPIServer) QuoteGet(w http.ResponseWriter, r *http.Request) {
	var nonce []byte
	if nonceB64 := r.URL.Query().Get("nonce"); nonceB64 != "" {
		var err error
		nonce, err = base64.URLEncoding.DecodeString(nonceB64)
		if err != nil {
			handler.WriteJSONFailure(w, nil, fmt.Sprintf("invalid query: bad nonce format: %s", err), http.StatusBadRequest)
			return
		}
	}

	cert, quote, err := s.api.GetCertQuote(r.Context(), nonce)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	handler.WriteJSON(w, CertQuoteResponse{cert, quote})
}

// RecoverPost performs recovery of the Coordinator enclave when unsealing of the existing state fails.
// This API endpoint is only available when the coordinator is in recovery mode.
func (s *ClientAPIServer) RecoverPost(w http.ResponseWriter, r *http.Request) {
	var req RecoveryRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 2048)).Decode(&req); err != nil {
		handler.WriteJSONFailure(w, nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Perform recover and receive amount of remaining secrets (for multi-party recovery)
	remaining, err := s.api.Recover(r.Context(), req.RecoverySecret)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Construct status message based on remaining keys
	var statusMessage string
	if remaining != 0 {
		statusMessage = fmt.Sprintf("Secret was processed successfully. Upload the next secret. Remaining secrets: %d", remaining)
	} else {
		statusMessage = "Recovery successful."
	}

	handler.WriteJSON(w, RecoveryResponse{
		Remaining: remaining,
		Message:   statusMessage,
	})
}

// SecretsGet retrieves secrets from the Coordinator.
// The secrets are requested via the query string in the form of ?s=<secretOne>&s=<secretTwo>&s=...
// and returned as a map of secret names to their respective values.
// The requesting user must be authorized to access the secrets.
func (s *ClientAPIServer) SecretsGet(w http.ResponseWriter, r *http.Request) {
	verifiedUser, err := handler.VerifyUser(s.api.VerifyUser, r)
	if err != nil {
		handler.WriteJSONFailure(w, nil, err.Error(), http.StatusUnauthorized)
		return
	}

	// Secrets are requested via the query string in the form of ?s=<secretOne>&s=<secretTwo>&s=...
	requestedSecrets := r.URL.Query()["s"]
	if len(requestedSecrets) <= 0 {
		handler.WriteJSONFailure(w, nil, "invalid query: endpoint requires at least one query parameter", http.StatusBadRequest)
		return
	}
	for _, req := range requestedSecrets {
		if len(req) <= 0 {
			handler.WriteJSONFailure(w, nil, "malformed query string: empty query parameter", http.StatusBadRequest)
			return
		}
	}

	secrets, err := s.api.GetSecrets(r.Context(), requestedSecrets, verifiedUser)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	handler.WriteJSON(w, SecretsGetResponse{Secrets: secrets})
}

// SecretsPost sets secrets in the Coordinator.
// The requesting user must be authorized to set the secrets.
func (s *ClientAPIServer) SecretsPost(w http.ResponseWriter, r *http.Request) {
	verifiedUser, err := handler.VerifyUser(s.api.VerifyUser, r)
	if err != nil {
		handler.WriteJSONFailure(w, nil, err.Error(), http.StatusUnauthorized)
		return
	}

	var req SecretsSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.WriteJSONFailure(w, nil, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.api.WriteSecrets(r.Context(), req.Secrets, verifiedUser); err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	handler.WriteJSON(w, nil)
}

// StatusGet retrieves the current status of the Coordinator.
func (s *ClientAPIServer) StatusGet(w http.ResponseWriter, r *http.Request) {
	statusCode, status, err := s.api.GetStatus(r.Context())
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	handler.WriteJSON(w, StatusResponse{
		Code:    int(statusCode),
		Message: status,
	})
}

// SignQuotePost receives an SGX quote and returns a signature for it.
// The Coordinator will verify the quote and sign it together with the TCB status of the quote using the root ECDSA key.
func (s *ClientAPIServer) SignQuotePost(w http.ResponseWriter, r *http.Request) {
	// Check if the current manifest allows signing quotes
	if !s.api.FeatureEnabled(r.Context(), manifest.FeatureSignQuoteEndpoint) {
		handler.WriteJSONError(w, "SignQuoteEndpoint feature is not enabled in the manifest", http.StatusForbidden)
		return
	}

	var req QuoteSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.WriteJSONFailure(
			w, map[string]string{"sgxQuote": "failed to parse JSON data"},
			fmt.Sprintf("bad request: %s", err), http.StatusBadRequest,
		)
		return
	}

	signature, tcbStatus, err := s.api.SignQuote(r.Context(), req.SGXQuote)
	if err != nil {
		var verifyErr *clientapi.QuoteVerifyError
		if errors.As(err, &verifyErr) {
			handler.WriteJSONFailure(
				w, map[string]string{"sgxQuote": verifyErr.Error()},
				"quote verification failed", http.StatusBadRequest,
			)
			return
		}

		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	handler.WriteJSON(w, QuoteSignResponse{
		VerificationSignature: signature,
		TCBStatus:             tcbStatus,
	})
}

// UpdateGet retrieves the update log of the Coordinator.
func (s *ClientAPIServer) UpdateGet(w http.ResponseWriter, r *http.Request) {
	updateLog, err := s.api.GetUpdateLog(r.Context())
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	handler.WriteJSON(w, UpdateLogResponse{UpdateLog: updateLog})
}

// UpdatePost applies an update to the Coordinator's manifest.
func (s *ClientAPIServer) UpdatePost(w http.ResponseWriter, r *http.Request) {
	verifiedUser, err := handler.VerifyUser(s.api.VerifyUser, r)
	if err != nil {
		handler.WriteJSONFailure(w, nil, err.Error(), http.StatusUnauthorized)
		return
	}

	var req UpdateApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.WriteJSONFailure(w, nil, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.api.UpdateManifest(r.Context(), req.Manifest, verifiedUser); err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	handler.WriteJSON(w, nil)
}
