// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package server

import (
	"encoding/json"
	"net/http"
)

// GeneralResponse is a wrapper for all our REST API responses to follow the JSend style: https://github.com/omniti-labs/jsend
type GeneralResponse struct {
	Status  string      `json:"status"`
	Data    interface{} `json:"data"`
	Message string      `json:"message,omitempty"` // only used when status = "error"
}

// CertQuoteResp wraps the certificate chain and quote for the client to use for remote attestation.
type CertQuoteResp struct {
	// A PEM-encoded certificate chain containing the Coordinator's Root CA and Intermediate CA,
	// which can be used for trust establishment between a client and the Coordinator.
	Cert string
	// Base64-encoded quote which can be used for Remote Attestation.
	Quote []byte
}

// StatusResp is a response.
type StatusResp struct {
	// 	A status code that matches the internal code of the Coordinator's current state.
	// example: 2
	StatusCode int
	// A descriptive status message of what the Coordinator expects the user to do in its current state.
	// example: Coordinator is ready to accept a manifest.
	StatusMessage string
}

// ManifestSignatureResp contains the manifest signature, a sha256 hash of the manifest, and the manifest itself.
type ManifestSignatureResp struct {
	// The manifest signature - signed by the root ECDSA key.
	// example: MEYCIQCmkqOP0Jf1v5ZR0vUYNnMxmy8j9aYR3Zdemuz8EXNQ4gIhAMk6MCg00Rowilui/66tHrkETMmkPmOktMKXQqv6NmnN
	// swagger:strfmt byte
	ManifestSignatureRootECDSA []byte
	// A SHA-256 of the currently set manifest. Does not change when an update has been applied.
	// example: 3fff78e99dd9bd801e0a3a22b7f7a24a492302c4d00546d18c7f7ed6e26e95c3
	ManifestSignature string
	// The currently set manifest in base64 encoding. Does not change when an update has been applied.
	Manifest []byte
}

// RecoveryDataResp contains RSA-encrypted AES state sealing key with public key specified by user in manifest.
type RecoveryDataResp struct {
	// An array containing key-value mappings for encrypted secrets to be used for recovering the Coordinator in case of disaster recovery.
	// The key matches each supplied key from RecoveryKeys in the manifest.
	RecoverySecrets map[string][]byte
}

// RecoveryV2Request is the request structure for the recovery process.
type RecoveryV2Request struct {
	// RecoverySecret is the decrypted secret (or secret share) to recover the Coordinator.
	RecoverySecret []byte `json:"recoverySecret"`
}

// RecoveryV2Resp contains the response for the recovery process.
type RecoveryV2Resp struct {
	// Remaining is the number of remaining secret shares to finish the recovery process.
	Remaining int `json:"remaining"`
	// Message is a human readable message about the recovery process.
	Message string `json:"message"`
}

// RecoveryStatusResp contains the status of the recovery process.
type RecoveryStatusResp struct {
	// StatusMessage holds information about the progress of the recovery.
	StatusMessage string
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	dataToReturn := GeneralResponse{Status: "success", Data: v}
	if err := json.NewEncoder(w).Encode(dataToReturn); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func writeJSONError(w http.ResponseWriter, errorString string, httpErrorCode int) {
	marshalledJSON, err := json.Marshal(GeneralResponse{Status: "error", Message: errorString})
	// Only fall back to non-JSON error when we cannot even marshal the error (which is pretty bad)
	if err != nil {
		http.Error(w, errorString, httpErrorCode)
	}
	http.Error(w, string(marshalledJSON), httpErrorCode)
}

func handleGetPost(getHandler, postHandler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getHandler(w, r)
		case http.MethodPost:
			postHandler(w, r)
		default:
			methodNotAllowedHandler(w, r)
		}
	}
}

func methodNotAllowedHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSONError(w, "", http.StatusMethodNotAllowed)
}
