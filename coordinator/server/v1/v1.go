// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package v1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// swagger:route GET /status status StatusGet
//
// Get the current status of the Coordinator.
//
// The status indicates the current state of the coordinator, and can be one of the following:
// 1. Coordinator is in recovery mode. Either upload a key to unseal the saved state, or set a new manifest. Waiting for user input on [/recover](../#/features/recovery.md).
// 1. Coordinator is ready to accept a manifest on [/manifest](../#/workflows/set-manifest.md)
// 1. Coordinator is running correctly and ready to accept marbles through the [Marble API](../#/workflows/add-service.md)
//
//	    Responses:
//	      200: StatusResponse
//			 500: ErrorResponse
func (s *ClientAPIServer) StatusGet(w http.ResponseWriter, r *http.Request) {
	statusCode, status, err := s.api.GetStatus(r.Context())
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	handler.WriteJSON(w, StatusResp{int(statusCode), status})
}

// swagger:route GET /manifest manifest ManifestGet
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
// ```bash
// curl --cacert marblerun.crt "https://$MARBLERUN/manifest" | jq '.data.ManifestSignature' --raw-output
// ```
//
// Example for verifying the deployed manifest via the intermediate key signature:
//
// ```bash
// # get manifest signature (signed by coordinator root key)
// curl --cacert marblerun.crt "https://$MARBLERUN/manifest" | jq '.data.ManifestSignatureRootECDSA' --raw-output | base64 -d > manifest.sig
// # extract root public key from coordinator certificate root
// marblerun certificate root $MARBLERUN
// openssl x509 -in marblerunRootCA.crt -pubkey -noout > root.pubkey
// # verify signature
// openssl dgst -sha256 -verify root.pubkey -signature manifest.sig manifest.json
// # verification fails? try to remove newlines from manifest
// awk 'NF {sub(/\r/, ""); printf "%s",$0;}' original.manifest.json  > formated.manifest.json
// ```
//
//	    Responses:
//	      200: ManifestResponse
//			 500: ErrorResponse
func (s *ClientAPIServer) ManifestGet(w http.ResponseWriter, r *http.Request) {
	signatureRootECDSA, manifest, err := s.api.GetManifestSignature(r.Context())
	if err != nil {
		// backwards compatibility, return empty response
		handler.WriteJSON(w, ManifestSignatureResp{
			ManifestSignatureRootECDSA: nil,
			ManifestSignature:          "",
			Manifest:                   nil,
		})
		return
	}

	fingerprint := sha256.Sum256(manifest)
	handler.WriteJSON(w, ManifestSignatureResp{
		ManifestSignatureRootECDSA: signatureRootECDSA,
		ManifestSignature:          hex.EncodeToString(fingerprint[:]),
		Manifest:                   manifest,
	})
}

// swagger:route POST /manifest manifest ManifestPost
//
// Set a manifest.
//
// Before deploying the application to the cluster the manifest needs to be set once by the provider.
// On success, an array containing key-value mapping for encrypted secrets to be used for recovering the Coordinator in case of disaster recovery.
// The key matches each supplied key from RecoveryKeys in the Manifest.
//
//	Example for setting the manifest with curl:
//
// ```bash
// curl --cacert marblerun.crt --data-binary @manifest.json "https://$MARBLERUN/manifest"
// ```
//
//	    Responses:
//	      200: RecoveryDataResponse
//			 500: ErrorResponse
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
		handler.WriteJSON(w, RecoveryDataResp{recoverySecretMap})
	} else {
		handler.WriteJSON(w, nil)
	}
}

// swagger:route GET /quote quote QuoteGet
//
// Retrieve a remote attestation quote and certificates.
//
// For retrieving a remote attestation quote over the whole cluster and the root certificate.
// The quote is an SGX-DCAP quote, you can learn more about DCAP in the [official Intel DCAP orientation](https://download.01.org/intel-sgx/sgx-dcap/1.9/linux/docs/Intel_SGX_DCAP_ECDSA_Orientation.pdf).
// Both the provider and the users of the confidential application can use this endpoint to verify the integrity of the Coordinator and the cluster at any time.
//
// The returned certificate chain is PEM-encoded, contains the Coordinator's Root CA and Intermediate CA, and can be used for trust establishment between a client and the Coordinator.
// The quote is base64-encoded and can be used for Remote Attestation, as described in [Verifying a deployment](../#/workflows/verification.md).
//
//	We provide a tool to automatically verify the quote and output the trusted certificate:
//
// ```bash
// # Either install era for the current user
// wget -P ~/.local/bin https://github.com/edgelesssys/era/releases/latest/download/era
// chmod +x ~/.local/bin/era
//
// # Or install it globally on your machine (requires root permissions)
// sudo wget -O /usr/local/bin/era https://github.com/edgelesssys/era/releases/latest/download/era
// sudo chmod +x /usr/local/bin/era
//
// era -c coordinator-era.json -h $MARBLERUN -o marblerun.crt
// ```
//
// > On Ubuntu, `~/.local/bin` is added to PATH only if the directory exists when the bash environment is initialized during login. You might need to re-login after creating the directory. Also, non-default shells such as `zsh` do not add this path by default. Therefore, if you receive `command not found: era` as an error message for a local user installation, either make sure `~/.local/bin` was added to your PATH successfully, or simply use the machine-wide installation method.
//
// The file `coordinator-era.json` contains the [Packages](../#/workflows/define-manifest.md#manifestpackages) information for the Coordinator.
// The example `coordinator-era.json` for our provided testing image can be downloaded from GitHub:
//
// ```bash
// wget https://github.com/edgelesssys/marblerun/releases/latest/download/coordinator-era.json
// ```
//
//	    Responses:
//	      200: CertQuoteResponse
//			 500: ErrorResponse
func (s *ClientAPIServer) QuoteGet(w http.ResponseWriter, r *http.Request) {
	cert, quote, err := s.api.GetCertQuote(r.Context(), nil)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	handler.WriteJSON(w, CertQuoteResp{cert, quote})
}

// swagger:route POST /recover recover RecoverPost
//
// Recover the Coordinator when unsealing of the existing state fails.
//
// This API endpoint is only available when the coordinator is in recovery mode.
// Before you can use the endpoint, you need to decrypt the recovery secret which you may have received when setting the manifest initially.
// See [Recovering the Coordinator](../#/workflows/recover-coordinator.md) to retrieve the recovery key needed to use this API endpoint correctly.
//
// Example for recovering the Coordinator with curl:
//
// ```bash
// curl -k -X POST --data-binary @recovery_key_decrypted "https://$MARBLERUN/recover"
// ```
//
//	    Responses:
//	      200: RecoveryStatusResponse
//			 500: ErrorResponse
func (s *ClientAPIServer) RecoverPost(w http.ResponseWriter, r *http.Request) {
	key, err := io.ReadAll(r.Body)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Perform recover and receive amount of remaining secrets (for multi-party recovery)
	remaining, err := s.api.Recover(r.Context(), key)
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

	handler.WriteJSON(w, RecoveryStatusResp{statusMessage})
}

// swagger:route GET /update update UpdateGet
//
// Get a log of all performed updates.
//
// Returns a structured log of all updates performed via the `/update` or `/secrets` endpoint, including timestamp, author, and affected resources.
//
//	    Responses:
//	      200: UpdateLogResponse
//			 500: ErrorResponse
func (s *ClientAPIServer) UpdateGet(w http.ResponseWriter, r *http.Request) {
	updateLog, err := s.api.GetUpdateLog(r.Context())
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	handler.WriteJSON(w, strings.Join(updateLog, "\n")+"\n")
}

// swagger:route POST /update update UpdatePost
//
// Update a specific package set in the manifest.
//
// This API endpoint only works if `Users` are defined in the Manifest.
// For more information, have a look at [updating a Manifest](../#/workflows/update-manifest.md).
//
// Example for updating the manifest with curl:
//
// ```bash
// curl --cacert marblerun.crt --cert user_certificate.crt --key user_private.key -w "%{http_code}" --data-binary @update_manifest.json https://$MARBLERUN/update
// ```
//
//	    Responses:
//	      200: SuccessResponse
//			 400: ErrorResponse
//			 500: ErrorResponse
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
	err = s.api.UpdateManifest(r.Context(), updateManifest, verifiedUser)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	handler.WriteJSON(w, nil)
}

// swagger:route GET /secrets secrets SecretsGet
//
// Retrieve secrets.
//
// Each requests allows specifying one or more secrets in the form of a query string, where each parameter `s` specifies one secret.
// A query string for the secrets `symmetricKeyShared` and `certShared` may look like the following:
//
// ```
// s=symmetricKeyShared&s=certShared
// ```
//
// This API endpoint only works when `Users` were defined in the manifest.
// The user connects via mutual TLS using the user client certificate in the TLS Handshake.
// For more information, look up [Managing secrets](../#/workflows/managing-secrets.md).
//
// Example for retrieving the secrets `symmetricKeyShared` and `certShared`:
//
// ```bash
// curl --cacert marblerun.crt --cert user_certificate.crt --key user_private.key https://$MARBLERUN/secrets?s=symmetricKeyShared&s=certShared
// ```
//
//	    Responses:
//	      200: SuccessResponse
//			 401: ErrorResponse
//			 500: ErrorResponse
func (s *ClientAPIServer) SecretsGet(w http.ResponseWriter, r *http.Request) {
	verifiedUser, err := handler.VerifyUser(s.api.VerifyUser, r)
	if err != nil {
		handler.WriteJSONError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Secrets are requested via the query string in the form of ?s=<secretOne>&s=<secretTwo>&s=...
	requestedSecrets := r.URL.Query()["s"]
	if len(requestedSecrets) <= 0 {
		handler.WriteJSONError(w, "invalid query", http.StatusBadRequest)
		return
	}
	for _, req := range requestedSecrets {
		if len(req) <= 0 {
			handler.WriteJSONError(w, "malformed query string", http.StatusBadRequest)
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

// swagger:route POST /secrets secrets SecretsPost
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
// ```bash
// curl --cacert marblerun.crt --cert user_certificate.crt --key user_private.key --data-binary @secrets.json https://$MARBLERUN/secrets
// ```
//
//	    Responses:
//	      200: SecretsMapResponse
//			 400: ErrorResponse
//			 401: ErrorResponse
//			 500: ErrorResponse
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
