/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package v1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/server/handler"
)

// ClientAPIServer serves the Coordinator's v1 REST API.
type ClientAPIServer struct {
	api handler.ClientAPI
}

// NewServer creates a new ClientAPIServer.
func NewServer(api handler.ClientAPI) *ClientAPIServer {
	return &ClientAPIServer{api: api}
}

// StatusGet retrieves the current status of the Coordinator.
//
// Get the current status of the Coordinator.
//
// The status indicates the current state of the coordinator, and can be one of the following:
// 1. Coordinator is in recovery mode. Either upload a key to unseal the saved state, or set a new manifest. Waiting for user input on [/recover](../#/features/recovery.md).
// 2. Coordinator is ready to accept a manifest on [/manifest](../#/workflows/set-manifest.md).
// 3. Coordinator is running correctly and ready to accept marbles through the [Marble API](../#/workflows/add-service.md).
func (s *ClientAPIServer) StatusGet(w http.ResponseWriter, r *http.Request) {
	statusCode, status, err := s.api.GetStatus(r.Context())
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	handler.WriteJSON(w, StatusResponse{int(statusCode), status})
}

// ManifestGet retrieves the currently set manifest.
//
// Get the currently set manifest.
//
// The endpoint returns a manifest signature as base64 encoded bytes
// (signed by the root ECDSA key) and a SHA-256 of the currently
// set manifest.
// Further, the manifest itself is returned as base64 encoded bytes.
// All returned values do not change when an update has been applied.
//
// Users can retrieve and inspect the manifest through this endpoint before interacting with the application.
//
// Example for requesting the deployed manifest hash with curl:
//
//	curl --cacert marblerun.crt "https://$MARBLERUN/manifest" | jq '.data.ManifestSignature' --raw-output
//
// Example for verifying the deployed manifest via the intermediate key signature:
//
//	# get manifest signature (signed by coordinator root key)
//	curl --cacert marblerun.crt "https://$MARBLERUN/manifest" | jq '.data.ManifestSignatureRootECDSA' --raw-output | base64 -d > manifest.sig
//	# extract root public key from coordinator certificate root
//	marblerun certificate root $MARBLERUN
//	openssl x509 -in marblerunRootCA.crt -pubkey -noout > root.pubkey
//	# verify signature
//	openssl dgst -sha256 -verify root.pubkey -signature manifest.sig manifest.json
//	# verification fails? try to remove newlines from manifest
//	awk 'NF {sub(/\r/, ""); printf "%s",$0;}' original.manifest.json  > formated.manifest.json
func (s *ClientAPIServer) ManifestGet(w http.ResponseWriter, r *http.Request) {
	signatureRootECDSA, manifest, err := s.api.GetManifestSignature(r.Context())
	if err != nil {
		// backwards compatibility, return empty response
		handler.WriteJSON(w, ManifestSignatureResponse{
			ManifestSignatureRootECDSA: nil,
			ManifestSignature:          "",
			Manifest:                   nil,
		})
		return
	}

	fingerprint := sha256.Sum256(manifest)
	handler.WriteJSON(w, ManifestSignatureResponse{
		ManifestSignatureRootECDSA: signatureRootECDSA,
		ManifestSignature:          hex.EncodeToString(fingerprint[:]),
		Manifest:                   manifest,
	})
}

// ManifestPost sets a manifest.
//
// Set a manifest.
//
// Before deploying the application to the cluster the manifest needs to be set once by the provider.
// On success, an array containing key-value mapping for encrypted secrets to be used for recovering the Coordinator in case of disaster recovery.
// The key matches each supplied key from RecoveryKeys in the Manifest.
//
//	Example for setting the manifest with curl:
//
//	curl --cacert marblerun.crt --data-binary @manifest.json "https://$MARBLERUN/manifest"
func (s *ClientAPIServer) ManifestPost(w http.ResponseWriter, r *http.Request) {
	manifest, err := io.ReadAll(r.Body)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	recoverySecretMap, err := s.api.SetManifest(r.Context(), manifest)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If recovery data is set, return it
	if len(recoverySecretMap) > 0 {
		handler.WriteJSON(w, RecoveryDataResponse{recoverySecretMap})
	} else {
		handler.WriteJSON(w, nil)
	}
}

// QuoteGet retrieves a remote attestation quote and certificates.
//
// Retrieve a remote attestation quote and certificates.
//
// For retrieving a remote attestation quote over the whole cluster and the root certificate.
// The quote is an SGX-DCAP quote, you can learn more about DCAP in the [official Intel DCAP orientation](https://download.01.org/intel-sgx/sgx-dcap/1.9/linux/docs/Intel_SGX_DCAP_ECDSA_Orientation.pdf).
// Both the provider and the users of the confidential application can use this endpoint to verify the integrity of the Coordinator and the cluster at any time.
//
// The returned certificate chain is PEM-encoded, contains the Coordinator's Root CA and Intermediate CA, and can be used for trust establishment between a client and the Coordinator.
// The quote is base64-encoded and can be used for Remote Attestation, as described in [Verifying a deployment](../#/workflows/verification.md).
func (s *ClientAPIServer) QuoteGet(w http.ResponseWriter, r *http.Request) {
	cert, quote, err := s.api.GetCertQuote(r.Context(), nil)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	handler.WriteJSON(w, CertQuoteResponse{cert, quote})
}

// RecoverPost is a handler for the removed /recover endpoint.
// It only exists to inform users about using the new /api/v2/recover endpoint.
func (s *ClientAPIServer) RecoverPost(w http.ResponseWriter, _ *http.Request) {
	errorMsg := "Recovering the Coordinator using the /recover API endpoint has been disabled. Use the /api/v2/recover endpoint instead."
	handler.WriteJSONError(w, errorMsg, http.StatusGone)
}

// UpdateGet retrieves the update log.
//
// Get a log of all performed updates.
//
// Returns a structured log of all updates performed via the `/update` or `/secrets` endpoint, including timestamp, author, and affected resources.
func (s *ClientAPIServer) UpdateGet(w http.ResponseWriter, r *http.Request) {
	updateLog, err := s.api.GetUpdateLog(r.Context())
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	handler.WriteJSON(w, strings.Join(updateLog, "\n")+"\n")
}

// UpdatePost updates a specific package set in the manifest.
//
// Update a specific package set in the manifest.
//
// This API endpoint only works if `Users` are defined in the Manifest.
// For more information, have a look at [updating a Manifest](../#/workflows/update-manifest.md).
//
// Example for updating the manifest with curl:
//
//	curl --cacert marblerun.crt --cert user_certificate.crt --key user_private.key -w "%{http_code}" --data-binary @update_manifest.json https://$MARBLERUN/update
func (s *ClientAPIServer) UpdatePost(w http.ResponseWriter, r *http.Request) {
	verifiedUser, err := handler.VerifyUser(s.api.VerifyUser, r)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	updateManifest, err := io.ReadAll(r.Body)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, _, err = s.api.UpdateManifest(r.Context(), updateManifest, verifiedUser); err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	handler.WriteJSON(w, nil)
}

// SecretsGet retrieves secrets.
//
// Retrieve secrets.
//
// Each requests allows specifying one or more secrets in the form of a query string, where each parameter `s` specifies one secret.
// A query string for the secrets `symmetricKeyShared` and `certShared` may look like the following:
//
//	s=symmetricKeyShared&s=certShared
//
// This API endpoint only works when `Users` were defined in the manifest.
// The user connects via mutual TLS using the user client certificate in the TLS Handshake.
// For more information, look up [Managing secrets](../#/workflows/managing-secrets.md).
//
// Example for retrieving the secrets `symmetricKeyShared` and `certShared`:
//
//	curl --cacert marblerun.crt --cert user_certificate.crt --key user_private.key https://$MARBLERUN/secrets?s=symmetricKeyShared&s=certShared
func (s *ClientAPIServer) SecretsGet(w http.ResponseWriter, r *http.Request) {
	verifiedUser, err := handler.VerifyUser(s.api.VerifyUser, r)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Secrets are requested via the query string in the form of ?s=<secretOne>&s=<secretTwo>&s=...
	requestedSecrets := r.URL.Query()["s"]
	if len(requestedSecrets) <= 0 {
		handler.WriteJSONError(w, "invalid query: endpoint requires at least one query parameter", http.StatusBadRequest)
		return
	}
	for _, req := range requestedSecrets {
		if len(req) <= 0 {
			handler.WriteJSONError(w, "malformed query string: empty query parameter", http.StatusBadRequest)
			return
		}
	}
	response, err := s.api.GetSecrets(r.Context(), requestedSecrets, verifiedUser)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	handler.WriteJSON(w, response)
}

// SecretsPost sets secrets.
//
// Set secrets.
//
// Setting secrets requires uploading them in JSON format.
//
// This API endpoint only works when `Users` were defined in the manifest.
// The user connects via mutual TLS using the user client certificate in the TLS Handshake.
// For more information, look up [Managing secrets](../#/workflows/managing-secrets.md).
//
// Example for setting secrets from the file `secrets.json`:
//
//	curl --cacert marblerun.crt --cert user_certificate.crt --key user_private.key --data-binary @secrets.json https://$MARBLERUN/secrets
func (s *ClientAPIServer) SecretsPost(w http.ResponseWriter, r *http.Request) {
	verifiedUser, err := handler.VerifyUser(s.api.VerifyUser, r)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	rawSecrets, err := io.ReadAll(r.Body)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var secrets map[string]manifest.UserSecret
	if err := json.Unmarshal(rawSecrets, &secrets); err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.api.WriteSecrets(r.Context(), secrets, verifiedUser); err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	handler.WriteJSON(w, nil)
}
