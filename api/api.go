// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/edgelesssys/marblerun/api/attestation"
	"github.com/edgelesssys/marblerun/api/rest"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	apiv2 "github.com/edgelesssys/marblerun/coordinator/server/v2"
	"github.com/edgelesssys/marblerun/internal/constants"
	"github.com/edgelesssys/marblerun/util"
	"github.com/spf13/afero"
)

var logSink = io.Discard

// SetLogSink sets the writer to which logs are written.
func SetLogSink(w io.Writer) {
	logSink = w
}

// VerifyCoordinator performs remote attestation on a MarbleRun Coordinator.
// On success, it returns the Coordinator's self signed root and intermediate certificates,
// as well as the verified SGX quote.
// The root certificate should be used by the client for future connections to the Coordinator.
// The SGX quote is returned to allow further verification, but this is purely optional.
//
// If this function is called from inside an EGo enclave, the "marblerun_ego_enclave" build tag must be set when building the binary.
func VerifyCoordinator(ctx context.Context, endpoint string, opts VerifyOptions) (rootCert *x509.Certificate, intermediateCert *x509.Certificate, sgxQuote []byte, err error) {
	opts.setDefaults()

	// Create a client to the Coordinator without a trusted root certificate
	// We will retrieve and verify the Coordinator's certificate using remote attestation
	client, err := rest.NewClient(endpoint, nil, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("setting up client: %w", err)
	}

	var args []string
	if len(opts.Nonce) > 0 {
		nonce := base64.URLEncoding.EncodeToString(opts.Nonce)
		args = []string{"nonce", nonce}
	}

	resp, err := client.Get(ctx, rest.V2API+rest.QuoteEndpoint, http.NoBody, args...)
	if rest.IsNotAllowedErr(err) {
		// Nonce is only supported in v2 API
		if len(opts.Nonce) > 0 {
			return nil, nil, nil, errors.New("using custom nonce requires /api/v2, but the Coordinator does not support /api/v2")
		}
		// Fall back to v1 API
		resp, err = client.Get(ctx, rest.QuoteEndpoint, http.NoBody)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("retrieving Coordinator quote: %w", err)
	}

	var response struct {
		Cert  string `json:"Cert"`
		Quote []byte `json:"Quote"`
	}
	if err := json.Unmarshal(resp, &response); err != nil {
		return nil, nil, nil, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}

	rootCert, intermediateCert, err = util.CoordinatorCertChainFromPEM([]byte(response.Cert))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing Coordinator certificate chain: %w", err)
	}

	// Return early if no quote verification should be performed
	if opts.InsecureSkipVerify {
		return rootCert, intermediateCert, response.Quote, nil
	}

	// Verify the SGX Quote against the Coordinator's certificate and the given configuration
	if err := attestation.VerifyCertificate(logSink, rootCert, response.Quote, attestation.Config{
		SecurityVersion:     opts.SecurityVersion,
		UniqueID:            opts.UniqueID,
		SignerID:            opts.SignerID,
		ProductID:           opts.ProductID,
		Debug:               opts.Debug,
		Nonce:               opts.Nonce,
		AcceptedTCBStatuses: opts.AcceptedTCBStatuses,
		AcceptedAdvisories:  opts.AcceptedAdvisories,
	}); err != nil {
		return nil, nil, nil, fmt.Errorf("verifying Coordinator quote: %w", err)
	}

	return rootCert, intermediateCert, sgxQuote, nil
}

// VerifyMarbleRunDeployment verifies a MarbleRun deployment by performing remote attestation on a Coordinator instance,
// and verifying that the deployment is using the expected manifest.
// On success, it returns the Coordinator's self signed root and intermediate certificates,
// as well as the verified SGX quote.
// The root certificate should be used by the client for future connections to the Coordinator.
// The SGX quote is returned to allow further verification, but this is purely optional.
//
// If this function is called from inside an EGo enclave, the "marblerun_ego_enclave" build tag must be set when building the binary.
func VerifyMarbleRunDeployment(ctx context.Context, endpoint string, opts VerifyOptions, manifest []byte) (rootCert *x509.Certificate, intermediateCert *x509.Certificate, sgxQuote []byte, err error) {
	opts.setDefaults()

	rootCert, intermediateCert, sgxQuote, err = VerifyCoordinator(ctx, endpoint, opts)
	if err != nil {
		return nil, nil, nil, err
	}

	// Verify that the Coordinator is using the expected manifest
	_, remoteHashHex, _, err := ManifestGet(ctx, endpoint, rootCert)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("getting Coordinator manifest: %w", err)
	}

	if remoteHashHex == "" {
		return nil, nil, nil, errors.New("Coordinator returned no manifest signature. Is the Coordinator in the correct state?")
	}

	remoteHash, err := hex.DecodeString(remoteHashHex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding Coordinator manifest hash: %w", err)
	}

	localHash := sha256.Sum256(manifest)
	// If the given data is exactly 32 bytes, assume it is already a hash of the manifest
	if len(manifest) == sha256.Size {
		localHash = [32]byte(manifest)
	}

	if !bytes.Equal(localHash[:], remoteHash) {
		return nil, nil, nil, fmt.Errorf(
			"MarbleRun deployment is using a different manifest than expected: manifest hash does not match local hash: %q != %q",
			remoteHashHex, hex.EncodeToString(localHash[:]),
		)
	}
	return rootCert, intermediateCert, sgxQuote, nil
}

// Recover performs recovery on a Coordinator instance by setting the decrypted recoverySecret.
// The signer is used to generate a signature over the recoverySecret.
// The Coordinator will verify this signature matches one of the recovery public keys set in the manifest.
// On success, it returns the number of remaining recovery secrets to be set,
// as well as the verified SGX quote.
//
// If this function is called from inside an EGo enclave, the "marblerun_ego_enclave" build tag must be set when building the binary.
func Recover(ctx context.Context, endpoint string, opts VerifyOptions, recoverySecret []byte, signer crypto.Signer) (remaining int, sgxQuote []byte, err error) {
	signature, err := util.SignPKCS1v15(signer, recoverySecret)
	if err != nil {
		return -1, nil, err
	}
	return recoverCoordinator(ctx, endpoint, opts, recoverySecret, signature)
}

// RecoverWithSignature performs recovery on a Coordinator instance by setting the decrypted recoverySecret.
// This is the same as [Recover], but allows passing in the recoverySecretSignature directly,
// instead of generating it using a [crypto.Signer].
// The recoveryKeySignature must be a PKCS#1 v1.5 signature over the SHA-256 hash of recoverySecret.
// recoverySecret may be encrypted using the Coordinator's ephemeral recovery key retrieved using [RecoveryPublicKey] and [EncryptRecoverySecretWithEphemeralKey],
// but the signature must always be generated over the plain recoverySecret.
//
// If this function is called from inside an EGo enclave, the "marblerun_ego_enclave" build tag must be set when building the binary.
func RecoverWithSignature(ctx context.Context, endpoint string, opts VerifyOptions, recoverySecret, recoverySecretSignature []byte) (remaining int, sgxQuote []byte, err error) {
	return recoverCoordinator(ctx, endpoint, opts, recoverySecret, recoverySecretSignature)
}

// RecoveryPublicKey retrieves the Coordinator's ephemeral recovery public key.
// The key can be used to encrypt recovery secrets before passing them to [RecoverWithSignature].
//
// If this function is called from inside an EGo enclave, the "marblerun_ego_enclave" build tag must be set when building the binary.
func RecoveryPublicKey(ctx context.Context, endpoint string, opts VerifyOptions) (pub crypto.PublicKey, sgxQuote []byte, err error) {
	opts.setDefaults()

	rootCert, _, sgxQuote, err := VerifyCoordinator(ctx, endpoint, opts)
	if err != nil {
		return nil, nil, err
	}

	client, err := rest.NewClient(endpoint, rootCert, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("setting up client: %w", err)
	}

	body, err := client.Get(ctx, "/api/v2/recover/public-key", http.NoBody)
	if err != nil {
		return nil, nil, fmt.Errorf("retrieving recovery public key: %w", err)
	}

	var response apiv2.RecoveryPublicKeyResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, nil, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}

	pubBlock, _ := pem.Decode(response.EphemeralPublicKey)
	if pubBlock == nil {
		return nil, nil, fmt.Errorf("decoding PEM block: %w", err)
	}
	pub, err = x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing public key: %w", err)
	}
	return pub, sgxQuote, nil
}

// EncryptRecoverySecretWithEphemeralKey encrypts a recovery secret using the ephemeral public key retrieved from [RecoveryPublicKey].
// The encrypted secret can be passed to [RecoverWithSignature].
func EncryptRecoverySecretWithEphemeralKey(recoverySecret []byte, recoveryPublicKey crypto.PublicKey) ([]byte, error) {
	switch pub := recoveryPublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, recoverySecret, nil)
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// DecryptRecoveryData decrypts recovery data returned by a Coordinator during [ManifestSet] using a parties private recovery key.
func DecryptRecoveryData(recoveryData []byte, recoveryPrivateKey crypto.Decrypter) ([]byte, error) {
	return recoveryPrivateKey.Decrypt(rand.Reader, recoveryData, &rsa.OAEPOptions{Hash: crypto.SHA256})
}

// GetStatus retrieves the status of a MarbleRun Coordinator instance.
//
// On success, returns one of the following:
//   - 0: recovery: the Coordinator failed to restart from an existing state and needs to be recovered manually
//   - 1: uninitialized: the Coordinator is currently initializing
//   - 2: waiting for manifest: Waiting for user to supply a manifest
//   - 3: accepting marbles: The Coordinator is running, and Marbles can be added to the deployment
func GetStatus(ctx context.Context, endpoint string, trustedRoot *x509.Certificate) (code int, msg string, err error) {
	client, err := rest.NewClient(endpoint, trustedRoot, nil)
	if err != nil {
		return -1, "", fmt.Errorf("setting up client: %w", err)
	}

	code, msg, err = getStatusV2(ctx, client)
	if rest.IsNotAllowedErr(err) {
		code, msg, err = getStatusV1(ctx, client)
	}
	if err != nil {
		return -1, "", fmt.Errorf("retrieving Coordinator status: %w", err)
	}

	return code, msg, nil
}

// ManifestGet retrieves the manifest of a MarbleRun deployment.
func ManifestGet(ctx context.Context, endpoint string, trustedRoot *x509.Certificate) (manifest []byte, manifestHash string, manifestSignatureECDSA []byte, err error) {
	client, err := rest.NewClient(endpoint, trustedRoot, nil)
	if err != nil {
		return nil, "", nil, fmt.Errorf("setting up client: %w", err)
	}

	manifest, manifestHash, manifestSignatureECDSA, err = manifestGetV2(ctx, client)
	if rest.IsNotAllowedErr(err) {
		manifest, manifestHash, manifestSignatureECDSA, err = manifestGetV1(ctx, client)
	}
	if err != nil {
		return nil, "", nil, fmt.Errorf("retrieving Coordinator manifest: %w", err)
	}
	return manifest, manifestHash, manifestSignatureECDSA, nil
}

// ManifestLog retrieves the update log of a MarbleRun deployment.
func ManifestLog(ctx context.Context, endpoint string, trustedRoot *x509.Certificate) ([]string, error) {
	client, err := rest.NewClient(endpoint, trustedRoot, nil)
	if err != nil {
		return nil, fmt.Errorf("setting up client: %w", err)
	}

	log, err := manifestLogV2(ctx, client)
	if rest.IsNotAllowedErr(err) {
		log, err = manifestLogV1(ctx, client)
	}
	if err != nil {
		return nil, fmt.Errorf("retrieving Coordinator update log: %w", err)
	}
	return log, nil
}

// ManifestSet sets the manifest for a MarbleRun deployment.
// If recovery secrets are defined, this function will return the encrypted recovery data.
func ManifestSet(ctx context.Context, endpoint string, trustedRoot *x509.Certificate, manifest []byte) (recoveryData map[string][]byte, err error) {
	client, err := rest.NewClient(endpoint, trustedRoot, nil)
	if err != nil {
		return nil, fmt.Errorf("setting up client: %w", err)
	}

	recoveryData, err = manifestSetV2(ctx, client, manifest)
	if rest.IsNotAllowedErr(err) {
		recoveryData, err = manifestSetV1(ctx, client, manifest)
	}
	if err != nil {
		return nil, fmt.Errorf("setting manifest: %w", err)
	}
	return recoveryData, nil
}

// ManifestUpdateApply sets a manifest update for a MarbleRun deployment.
// On a complete manifest update, returns a list of users that may acknowledge the update
// and the number of remaining acknowledgements before the update is applied.
func ManifestUpdateApply(ctx context.Context, endpoint string, trustedRoot *x509.Certificate, updateManifest []byte, clientKeyPair *tls.Certificate) ([]string, int, error) {
	client, err := rest.NewClient(endpoint, trustedRoot, clientKeyPair)
	if err != nil {
		return nil, 0, fmt.Errorf("setting up client: %w", err)
	}

	missingUsers, missingAcks, err := manifestUpdateApplyV2(ctx, client, updateManifest)
	if rest.IsNotAllowedErr(err) {
		missingAcks = 0
		missingUsers = nil
		err = manifestUpdateApplyV1(ctx, client, updateManifest)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("applying manifest update: %w", err)
	}
	return missingUsers, missingAcks, nil
}

// ManifestUpdateGet retrieves a pending manifest update of a MarbleRun deployment.
func ManifestUpdateGet(ctx context.Context, endpoint string, trustedRoot *x509.Certificate) (pendingManifest []byte, missingUsers []string, err error) {
	client, err := rest.NewClient(endpoint, trustedRoot, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("setting up client: %w", err)
	}

	resp, err := client.Get(ctx, rest.V2API+rest.UpdateStatusEndpoint, http.NoBody)
	if rest.IsNotAllowedErr(err) {
		resp, err = client.Get(ctx, rest.UpdateStatusEndpoint, http.NoBody)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("retrieving pending manifest update: %w", err)
	}

	var response struct {
		Manifest     []byte   `json:"manifest"`
		MissingUsers []string `json:"missingUsers"`
	}
	if err := json.Unmarshal(resp, &response); err != nil {
		return nil, nil, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}

	return response.Manifest, response.MissingUsers, nil
}

// ManifestUpdateAcknowledge acknowledges the pending manifest update of a MarbleRun deployment.
// On success, it returns the number of remaining acknowledgements before the update is applied.
func ManifestUpdateAcknowledge(
	ctx context.Context, endpoint string, trustedRoot *x509.Certificate, updateManifest []byte, clientKeyPair *tls.Certificate,
) (missingUsers []string, missingAcknowledgements int, err error) {
	client, err := rest.NewClient(endpoint, trustedRoot, clientKeyPair)
	if err != nil {
		return nil, -1, fmt.Errorf("setting up client: %w", err)
	}

	// Attempt to acknowledge the update using the v2 API first
	missingUsers, missingAcknowledgements, err = manifestUpdateAcknowledgeV2(ctx, client, updateManifest)
	if rest.IsNotAllowedErr(err) {
		missingUsers, missingAcknowledgements, err = manifestUpdateAcknowledgeV1(ctx, client, updateManifest)
	}
	if err != nil {
		return nil, -1, fmt.Errorf("sending manifest update acknowledgement: %w", err)
	}
	return missingUsers, missingAcknowledgements, err
}

// ManifestUpdateCancel cancels a pending manifest update of a MarbleRun deployment.
func ManifestUpdateCancel(ctx context.Context, endpoint string, trustedRoot *x509.Certificate, clientKeyPair *tls.Certificate) error {
	client, err := rest.NewClient(endpoint, trustedRoot, clientKeyPair)
	if err != nil {
		return fmt.Errorf("setting up client: %w", err)
	}

	// Attempt to cancel the update using the v2 API first
	_, err = client.Post(ctx, rest.V2API+rest.UpdateCancelEndpoint, "", http.NoBody)
	if rest.IsNotAllowedErr(err) {
		_, err = client.Post(ctx, rest.UpdateCancelEndpoint, "", http.NoBody)
	}
	if err != nil {
		return fmt.Errorf("sending manifest update cancel: %w", err)
	}
	return nil
}

// SecretGet retrieves secrets from a MarbleRun deployment.
func SecretGet(ctx context.Context, endpoint string, trustedRoot *x509.Certificate, clientKeyPair *tls.Certificate, secrets []string) (map[string]manifest.Secret, error) {
	client, err := rest.NewClient(endpoint, trustedRoot, clientKeyPair)
	if err != nil {
		return nil, fmt.Errorf("setting up client: %w", err)
	}

	var query []string
	for _, secretID := range secrets {
		query = append(query, "s", secretID)
	}

	secretMap, err := secretGetV2(ctx, client, query)
	if rest.IsNotAllowedErr(err) {
		secretMap, err = secretGetV1(ctx, client, query)
	}
	if err != nil {
		return nil, fmt.Errorf("retrieving secrets: %w", err)
	}
	return secretMap, nil
}

// SecretSet sets secrets for a MarbleRun deployment.
func SecretSet(ctx context.Context, endpoint string, trustedRoot *x509.Certificate, clientKeyPair *tls.Certificate, secrets map[string]manifest.UserSecret) error {
	client, err := rest.NewClient(endpoint, trustedRoot, clientKeyPair)
	if err != nil {
		return fmt.Errorf("setting up client: %w", err)
	}

	err = secretSetV2(ctx, client, secrets)
	if rest.IsNotAllowedErr(err) {
		err = secretSetV1(ctx, client, secrets)
	}
	if err != nil {
		return fmt.Errorf("setting secrets: %w", err)
	}
	return nil
}

// SetMonotonicCounter increases a monotonic counter managed by the Coordinator.
//
// This function can only be called by a Marble. The counter is bound to the Marble's type and UUID.
//
// If the passed value is greater than the counter's value, it is set as the new value and the old value is returned.
// Otherwise, the value is not changed and the current value is returned.
func SetMonotonicCounter(ctx context.Context, endpoint string, name string, value uint64) (uint64, error) {
	marbleKeyPair, trustedRoot, err := getMarbleCredentialsFromEnv()
	if err != nil {
		return 0, fmt.Errorf("getting credentials from secure environment: %w", err)
	}

	client, err := rest.NewClient(endpoint, trustedRoot, &marbleKeyPair)
	if err != nil {
		return 0, fmt.Errorf("setting up client: %w", err)
	}

	reqBody, err := json.Marshal(apiv2.MonotonicCounterRequest{Name: name, Value: value})
	if err != nil {
		return 0, fmt.Errorf("marshalling request: %w", err)
	}

	resp, err := client.Post(ctx, rest.V2API+rest.MonotonicCounterEndpoint, rest.ContentJSON, bytes.NewReader(reqBody))
	if err != nil {
		return 0, fmt.Errorf("sending request: %w", err)
	}

	var response apiv2.MonotonicCounterResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		return 0, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}

	return response.Value, nil
}

// SignQuote sends an SGX quote to a Coordinator for signing.
// If the quote is valid, the Coordinator will sign the quote using its root ECDSA key, and return the signature with the TCB status of the quote.
// The Coordinator does not verify if the quote matches any packages in the configured manifest.
// The signature is created over the SHA-256 hash of the base64-encoded SGX quote and the TCB status:
//
//	signature = ECDSA_sign(root_priv_key, SHA256(base64(SGX_quote) + string(TCB_status)))
//
// Use [VerifySignedQuote] to verify the signature.
func SignQuote(ctx context.Context, endpoint string, trustedRoot *x509.Certificate, sgxQuote []byte) (signature []byte, tcbStatus tcbstatus.Status, err error) {
	client, err := rest.NewClient(endpoint, trustedRoot, nil)
	if err != nil {
		return nil, tcbstatus.Unknown, fmt.Errorf("setting up client: %w", err)
	}

	signReq, err := json.Marshal(apiv2.QuoteSignRequest{SGXQuote: sgxQuote})
	if err != nil {
		return nil, tcbstatus.Unknown, fmt.Errorf("marshalling quote sign request: %w", err)
	}

	resp, err := client.Post(ctx, rest.V2API+rest.SignQuoteEndpoint, rest.ContentJSON, bytes.NewReader(signReq))
	if err != nil {
		return nil, tcbstatus.Unknown, fmt.Errorf("sending quote sign request: %w", err)
	}

	var response apiv2.QuoteSignResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		return nil, tcbstatus.Unknown, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}

	switch response.TCBStatus {
	case tcbstatus.UpToDate.String():
		tcbStatus = tcbstatus.UpToDate
	case tcbstatus.OutOfDate.String():
		tcbStatus = tcbstatus.OutOfDate
	case tcbstatus.Revoked.String():
		tcbStatus = tcbstatus.Revoked
	case tcbstatus.ConfigurationNeeded.String():
		tcbStatus = tcbstatus.ConfigurationNeeded
	case tcbstatus.OutOfDateConfigurationNeeded.String():
		tcbStatus = tcbstatus.OutOfDateConfigurationNeeded
	case tcbstatus.SWHardeningNeeded.String():
		tcbStatus = tcbstatus.SWHardeningNeeded
	case tcbstatus.ConfigurationAndSWHardeningNeeded.String():
		tcbStatus = tcbstatus.ConfigurationAndSWHardeningNeeded
	default:
		return nil, tcbstatus.Unknown, fmt.Errorf("Coordinator returned unknown TCB status: %q", response.TCBStatus)
	}

	return response.VerificationSignature, tcbStatus, nil
}

// VerifySignedQuote verifies an SGX quote against the signature created by a Coordinator.
func VerifySignedQuote(trustedRoot *x509.Certificate, sgxQuote []byte, signature []byte, tcbStatus tcbstatus.Status) bool {
	expected := sha256.Sum256([]byte(base64.StdEncoding.EncodeToString(sgxQuote) + tcbStatus.String()))
	rootPub, ok := trustedRoot.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	return ecdsa.VerifyASN1(rootPub, expected[:], signature)
}

// VerifyOptions specifies how to verify the remote attestation of a Coordinator instances.
type VerifyOptions struct {
	// InsecureSkipVerify disables verification of the Coordinator's attestation statement.
	// WARNING: This IS insecure and should only be used for testing purposes.
	InsecureSkipVerify bool `json:"InsecureSkipVerify"`

	// UniqueID is the unique ID (MRENCLAVE) of the Coordinator enclave.
	UniqueID string `json:"UniqueID"`
	// SignerID is the signer ID (MRSIGNER) of the Coordinator enclave.
	SignerID string `json:"SignerID"`
	// SecurityVersion is the security version (ISVSVN) of the Coordinator enclave.
	SecurityVersion uint `json:"SecurityVersion"`
	// ProductID is the product ID (ISVPRODID) of the Coordinator enclave.
	ProductID uint16 `json:"ProductID"`
	// Debug specifies whether the Coordinator enclave is allowed to run in debug mode.
	Debug bool `json:"Debug"`

	// AcceptedTCBStatuses is a list of TCB statuses that are considered valid.
	// Should be one or multiple from {"UpToDate", "OutOfDate",	"Revoked", "ConfigurationNeeded", "OutOfDateConfigurationNeeded", "SWHardeningNeeded", "ConfigurationAndSWHardeningNeeded"}.
	// If not set, defaults to ["UpToDate", "SWHardeningNeeded"].
	// If the Coordinator returns a TCB status not listed, an [attestation.TCBStatusError] is returned.
	AcceptedTCBStatuses []string `json:"AcceptedTCBStatuses"`
	// AcceptedAdvisories is a list of Intel Security Advisories that are acceptable.
	// If the Coordinator returns TCB status "SWHardeningNeeded", the list of advisories for that report must be a subset of this list.
	// If not set, all advisories are accepted.
	AcceptedAdvisories []string `json:"AcceptedAdvisories"`

	// Nonce is an optional, user-defined nonce to be included in the Coordinator's attestation statement.
	// If set, the Coordinator will generate an SGX quote over sha256(Coordinator_root_cert, Nonce).
	// Set a nonce if you want to enforce freshness of the quote. The API functions will automatically verify that the returned quote includes this nonce.
	Nonce []byte `json:"Nonce"`
}

// VerifyOptionsFromConfig reads a configuration file from disk.
func VerifyOptionsFromConfig(configPath string) (VerifyOptions, error) {
	fs := afero.NewOsFs()
	return verifyOptionsFromConfig(afero.Afero{Fs: fs}, configPath)
}

func (v *VerifyOptions) setDefaults() {
	if len(v.AcceptedTCBStatuses) == 0 {
		v.AcceptedTCBStatuses = []string{"UpToDate", "SWHardeningNeeded"}
	}
}

func verifyOptionsFromConfig(fs afero.Afero, configPath string) (VerifyOptions, error) {
	var opts VerifyOptions
	optsRaw, err := fs.ReadFile(configPath)
	if err != nil {
		return opts, err
	}
	err = json.Unmarshal(optsRaw, &opts)
	return opts, err
}

func getByteEnv(name string) ([]byte, error) {
	value := os.Getenv(name)
	if len(value) == 0 {
		return nil, fmt.Errorf("environment variable not set: %s", name)
	}
	return []byte(value), nil
}

func getMarbleCredentialsFromEnv() (tls.Certificate, *x509.Certificate, error) {
	certChain, err := getByteEnv(constants.MarbleEnvironmentCertificateChain)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	rootCA, err := getByteEnv(constants.MarbleEnvironmentCoordinatorRootCA)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafPrivk, err := getByteEnv(constants.MarbleEnvironmentPrivateKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	block, _ := pem.Decode(rootCA)
	if block == nil {
		return tls.Certificate{}, nil, errors.New("decoding Coordinator root certificate failed")
	}
	coordinatorRoot, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("parsing Coordinator root certificate: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certChain, leafPrivk)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("creating TLS key pair: %w", err)
	}

	return tlsCert, coordinatorRoot, nil
}

// recoverCoordinator performs recovery on a Coordinator instance by setting the decrypted recoverySecret.
// The signer is used to generate a signature over the recoverySecret.
// The Coordinator will verify this signature matches one of the recovery public keys set in the manifest.
// On success, it returns the number of remaining recovery secrets to be set,
// as well as the verified SGX quote.
func recoverCoordinator(ctx context.Context, endpoint string, opts VerifyOptions, recoverySecret, recoverySecretSignature []byte) (remaining int, sgxQuote []byte, err error) {
	opts.setDefaults()

	rootCert, _, sgxQuote, err := VerifyCoordinator(ctx, endpoint, opts)
	if err != nil {
		return -1, nil, err
	}

	client, err := rest.NewClient(endpoint, rootCert, nil)
	if err != nil {
		return -1, nil, fmt.Errorf("setting up client: %w", err)
	}

	// The v1 API does not support recovery, therefore only attempt the v2 API
	remaining, err = recoverV2(ctx, client, recoverySecret, recoverySecretSignature)
	if err != nil {
		return -1, nil, fmt.Errorf("sending recovery request: %w", err)
	}

	return remaining, sgxQuote, err
}
