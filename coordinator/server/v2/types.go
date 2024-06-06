// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package v2

import "github.com/edgelesssys/marblerun/coordinator/manifest"

// CertQuoteResponse wraps the certificate chain and quote for the client to use for remote attestation.
type CertQuoteResponse struct {
	// A PEM-encoded certificate chain containing the Coordinator's Root CA and Intermediate CA,
	// which can be used for trust establishment between a client and the Coordinator.
	Cert string `json:"cert"`
	// Base64-encoded quote which can be used for Remote Attestation.
	Quote []byte `json:"quote"`
}

// ManifestGetResponse contains the manifest signature, a SHA-256 hash of the manifest, and the manifest itself.
type ManifestGetResponse struct {
	// ManifestSignatureRootECDSA is an ASN.1 encoded ECDSA signature using the Coordinator's root ECDSA key
	// over the sha256 hash of the manifest
	ManifestSignatureRootECDSA []byte `json:"manifestSignatureRootECDSA"`
	// ManifestFingerprint is SHA-256 hash of the currently set manifest.
	// It does not change when a package update has been applied.
	ManifestFingerprint string `json:"manifestFingerprint"`
	// Manifest is the currently set manifest of the Coordinator.
	// It does not change when a package update has been applied.
	Manifest []byte `json:"manifest"`
}

// ManifestSetRequest is the request structure for setting the manifest.
type ManifestSetRequest struct {
	// Manifest is the new manifest to set.
	Manifest []byte `json:"manifest"`
}

// ManifestSetResponse contains the response to setting the manifest.
type ManifestSetResponse struct {
	// RecoverySecrets is a map containing the encrypted secrets to be used for recovering the Coordinator.
	// The map keys match the names of the supplied RecoveryKeys in the manifest.
	RecoverySecrets map[string][]byte
}

// QuoteSignRequest contains an SGX Quote to be verified and signed by the Coordinator.
type QuoteSignRequest struct {
	// SGXQuote is the raw SGX quote data.
	SGXQuote []byte `json:"sgxQuote"`
}

// QuoteSignResponse contains the SGX Quote signature created by the Coordinator using its root ECDSA key,
// as well as the TCB status of the Quote.
type QuoteSignResponse struct {
	// TCBStatus is the TCB status of the SGX Quote.
	TCBStatus string `json:"tcbStatus"`
	// VerificationSignature is a signature over sha256(base64(SGXQuote)|TCBStatus) signed by the root ECDSA key.
	VerificationSignature []byte `json:"verificationSignature"`
}

// RecoveryRequest is the request structure for the recovery process.
type RecoveryRequest struct {
	// RecoverySecret is the decrypted secret (or secret share) to recover the Coordinator.
	RecoverySecret []byte `json:"recoverySecret"`
}

// RecoveryResponse contains the response for the recovery process.
type RecoveryResponse struct {
	// Remaining is the number of remaining secret shares to finish the recovery process.
	Remaining int `json:"remaining"`
	// Message is a human readable message about the recovery process.
	Message string `json:"message"`
}

// SecretsGetResponse is the response when retrieving secrets from the Coordinator.
type SecretsGetResponse struct {
	// Secrets is a map containing the requested secrets.
	Secrets map[string]manifest.Secret `json:"secrets"`
}

// SecretsSetRequest is the request structure for setting secrets in the Coordinator.
// The requesting user must be authorized to set the secrets.
type SecretsSetRequest struct {
	// Secrets is a map containing the secrets to set.
	Secrets map[string]manifest.UserSecret `json:"secrets"`
}

// StatusResponse is the response to a status request.
type StatusResponse struct {
	// Code that matches the internal code of the Coordinator's current state.
	// One of:
	//  1: Recovery mode
	//  2: Ready to accept manifest
	//  3: Coordinator is running and ready to accept Marbles
	Code int `json:"code"`
	// Message is a human readable message of what the Coordinator expects the user to do in its current state.
	// example: Coordinator is ready to accept a manifest.
	Message string `json:"message"`
}

// UpdateLogResponse is the response to an update log request.
type UpdateLogResponse struct {
	// UpdateLog is a list of strings where each string is a log entry of the Coordinator's update log.
	UpdateLog []string `json:"updateLog"`
}

// UpdateApplyRequest is the request structure for applying an update.
type UpdateApplyRequest struct {
	// Manifest is the new manifest to apply.
	Manifest []byte `json:"manifest"`
}
