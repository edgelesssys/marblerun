/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package v1

// CertQuoteResponse wraps the certificate chain and quote for the client to use for remote attestation.
type CertQuoteResponse struct {
	// A PEM-encoded certificate chain containing the Coordinator's Root CA and Intermediate CA,
	// which can be used for trust establishment between a client and the Coordinator.
	Cert string
	// Base64-encoded quote which can be used for Remote Attestation.
	Quote []byte
}

// StatusResponse is a response.
type StatusResponse struct {
	// 	A status code that matches the internal code of the Coordinator's current state.
	// example: 2
	StatusCode int
	// A descriptive status message of what the Coordinator expects the user to do in its current state.
	// example: Coordinator is ready to accept a manifest.
	StatusMessage string
}

// ManifestSignatureResponse contains the manifest signature, a sha256 hash of the manifest, and the manifest itself.
type ManifestSignatureResponse struct {
	// The manifest signature - signed by the root ECDSA key.
	// example: MEYCIQCmkqOP0Jf1v5ZR0vUYNnMxmy8j9aYR3Zdemuz8EXNQ4gIhAMk6MCg00Rowilui/66tHrkETMmkPmOktMKXQqv6NmnN
	// swagger:strfmt byte
	ManifestSignatureRootECDSA []byte
	// A SHA-256 of the currently set manifest. Does not change when an update has been applied.
	// example: 3fff78e99dd9bd801e0a3a22b7f7a24a492302c4d00546d18c7f7ed6e26e95c3
	ManifestSignature string
	// The currently set manifest. Does not change when an update has been applied.
	Manifest []byte
}

// RecoveryDataResponse contains RSA-encrypted AES state sealing key with public key specified by user in manifest.
type RecoveryDataResponse struct {
	// An array containing key-value mappings for encrypted secrets to be used for recovering the Coordinator in case of disaster recovery.
	// The key matches each supplied key from RecoveryKeys in the manifest.
	RecoverySecrets map[string][]byte
}

// RecoveryStatusResponse contains the status of the recovery process.
type RecoveryStatusResponse struct {
	// StatusMessage holds information about the progress of the recovery.
	StatusMessage string
}
