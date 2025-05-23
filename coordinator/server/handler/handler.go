/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package handler

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/user"
	"github.com/google/uuid"
)

// ClientAPI is the interface implementing the backend logic of the REST API.
type ClientAPI interface {
	SetManifest(ctx context.Context, rawManifest []byte) (recoverySecretMap map[string][]byte, err error)
	GetCertQuote(ctx context.Context, nonce []byte) (cert string, certQuote []byte, err error)
	GetManifestSignature(context.Context) (manifestSignatureRootECDSA, manifest []byte, err error)
	GetSecrets(ctx context.Context, requestedSecrets []string, requestUser *user.User) (map[string]manifest.Secret, error)
	GetStatus(context.Context) (statusCode state.State, status string, err error)
	GetUpdateLog(context.Context) (updateLog []string, err error)
	Recover(ctx context.Context, encryptionKey, encryptionKeySignature []byte) (int, error)
	SetMonotonicCounter(ctx context.Context, marbleType string, marbleUUID uuid.UUID, name string, value uint64) (uint64, error)
	SignQuote(ctx context.Context, quote []byte) (signature []byte, tcbStatus string, err error)
	VerifyMarble(ctx context.Context, clientCerts []*x509.Certificate) (string, uuid.UUID, error)
	VerifyUser(ctx context.Context, clientCerts []*x509.Certificate) (*user.User, error)
	UpdateManifest(ctx context.Context, rawUpdateManifest []byte, updater *user.User) ([]string, int, error)
	WriteSecrets(ctx context.Context, secrets map[string]manifest.UserSecret, updater *user.User) error
	FeatureEnabled(ctx context.Context, feature string) bool
}

// GeneralResponse is a wrapper for all our REST API responses to follow the JSend style: https://github.com/omniti-labs/jsend
type GeneralResponse struct {
	Status  string      `json:"status"`
	Data    interface{} `json:"data"`
	Message string      `json:"message,omitempty"` // only used when status = "error"
}

// GetPost is a helper function to assign different handlers depending on the HTTP method.
func GetPost(getHandler, postHandler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getHandler(w, r)
		case http.MethodPost:
			postHandler(w, r)
		default:
			MethodNotAllowedHandler(w, r)
		}
	}
}

// VerifyMarble checks if the Marble is authorized to access the API.
func VerifyMarble(verifyFunc func(context.Context, []*x509.Certificate) (string, uuid.UUID, error), r *http.Request) (string, uuid.UUID, error) {
	// Abort if no client certificate was provided
	if r.TLS == nil {
		return "", uuid.UUID{}, errors.New("no client certificate provided")
	}
	marbleType, marbleUUID, err := verifyFunc(r.Context(), r.TLS.PeerCertificates)
	if err != nil {
		return "", uuid.UUID{}, fmt.Errorf("unauthorized marble: %w", err)
	}
	return marbleType, marbleUUID, nil
}

// VerifyUser checks if the user is authorized to access the API.
func VerifyUser(verifyFunc func(context.Context, []*x509.Certificate) (*user.User, error), r *http.Request) (*user.User, error) {
	// Abort if no user client certificate was provided
	if r.TLS == nil {
		return nil, errors.New("no client certificate provided")
	}
	verifiedUser, err := verifyFunc(r.Context(), r.TLS.PeerCertificates)
	if err != nil {
		return nil, fmt.Errorf("unauthorized user: %w", err)
	}
	return verifiedUser, nil
}

// WriteJSON writes a JSend response to the given http.ResponseWriter.
func WriteJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	dataToReturn := GeneralResponse{Status: "success", Data: v}
	if err := json.NewEncoder(w).Encode(dataToReturn); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// WriteJSONError writes a JSend error response to the given http.ResponseWriter.
func WriteJSONError(w http.ResponseWriter, errorString string, httpErrorCode int) {
	marshalledJSON, err := json.Marshal(GeneralResponse{Status: "error", Message: errorString})
	// Only fall back to non-JSON error when we cannot even marshal the error (which is pretty bad)
	if err != nil {
		http.Error(w, errorString, httpErrorCode)
	}
	http.Error(w, string(marshalledJSON), httpErrorCode)
}

// WriteJSONFailure writes a JSend failure response to the given http.ResponseWriter.
func WriteJSONFailure(w http.ResponseWriter, v interface{}, message string, httpErrorCode int) {
	w.Header().Set("Content-Type", "application/json")
	dataToReturn := GeneralResponse{Status: "fail", Data: v, Message: message}
	w.WriteHeader(httpErrorCode)
	if err := json.NewEncoder(w).Encode(dataToReturn); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// MethodNotAllowedHandler returns a 405 Method Not Allowed error.
func MethodNotAllowedHandler(w http.ResponseWriter, _ *http.Request) {
	WriteJSONError(w, "", http.StatusMethodNotAllowed)
}
