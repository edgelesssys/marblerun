// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/edgelesssys/marblerun/api/attestation"
	"github.com/edgelesssys/marblerun/api/internal/rest"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/server"
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
	path := rest.QuoteEndpoint
	if len(opts.Nonce) > 0 {
		nonce := base64.URLEncoding.EncodeToString(opts.Nonce)
		args = []string{"nonce", nonce}
		path = rest.V2API + rest.QuoteEndpoint // Nonce is only supported in v2 API
	}
	resp, err := client.Get(ctx, path, http.NoBody, args...)
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
// On success, it returns the number of remaining recovery secrets to be set,
// as well as the verified SGX quote.
//
// If this function is called from inside an EGo enclave, the "marblerun_ego_enclave" build tag must be set when building the binary.
func Recover(ctx context.Context, endpoint string, opts VerifyOptions, recoverySecret []byte) (remaining int, sgxQuote []byte, err error) {
	opts.setDefaults()

	rootCert, _, sgxQuote, err := VerifyCoordinator(ctx, endpoint, opts)
	if err != nil {
		return -1, nil, err
	}

	client, err := rest.NewClient(endpoint, rootCert, nil)
	if err != nil {
		return -1, nil, fmt.Errorf("setting up client: %w", err)
	}

	// Attempt recovery using the v2 API first
	remaining, err = recoverV2(ctx, client, recoverySecret)
	if err != nil {
		// If the Coordinator does not support the v2 API, fall back to v1
		var notAllowedErr *rest.NotAllowedError
		if !errors.As(err, &notAllowedErr) {
			return -1, nil, fmt.Errorf("sending recovery request: %w", err)
		}

		remaining, err = recoverV1(ctx, client, recoverySecret)
	}
	return remaining, sgxQuote, err
}

// DecryptRecoveryData decrypts recovery data returned by a Coordinator during [ManifestSet] using a parties private recovery key.
func DecryptRecoveryData(recoveryData []byte, recoveryPrivateKey *rsa.PrivateKey) ([]byte, error) {
	return util.DecryptOAEP(recoveryPrivateKey, recoveryData)
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
	resp, err := client.Get(ctx, rest.StatusEndpoint, http.NoBody)
	if err != nil {
		return -1, "", fmt.Errorf("retrieving Coordinator status: %w", err)
	}

	var response struct {
		Code int    `json:"StatusCode"`
		Msg  string `json:"StatusMessage"`
	}
	if err := json.Unmarshal(resp, &response); err != nil {
		return -1, "", fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}
	return response.Code, response.Msg, nil
}

// ManifestGet retrieves the manifest of a MarbleRun deployment.
func ManifestGet(ctx context.Context, endpoint string, trustedRoot *x509.Certificate) (manifest []byte, manifestHash string, manifestSignatureECDSA []byte, err error) {
	client, err := rest.NewClient(endpoint, trustedRoot, nil)
	if err != nil {
		return nil, "", nil, fmt.Errorf("setting up client: %w", err)
	}
	resp, err := client.Get(ctx, rest.ManifestEndpoint, http.NoBody)
	if err != nil {
		return nil, "", nil, fmt.Errorf("retrieving Coordinator manifest: %w", err)
	}

	var response server.ManifestSignatureResp
	if err := json.Unmarshal(resp, &response); err != nil {
		return nil, "", nil, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}

	return response.Manifest, response.ManifestSignature, response.ManifestSignatureRootECDSA, nil
}

// ManifestLog retrieves the update log of a MarbleRun deployment.
func ManifestLog(ctx context.Context, endpoint string, trustedRoot *x509.Certificate) ([]string, error) {
	client, err := rest.NewClient(endpoint, trustedRoot, nil)
	if err != nil {
		return nil, fmt.Errorf("setting up client: %w", err)
	}
	resp, err := client.Get(ctx, rest.UpdateEndpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("retrieving Coordinator update log: %w", err)
	}
	return strings.Split(strings.TrimSpace(string(resp)), "\n"), nil
}

// ManifestSet sets the manifest for a MarbleRun deployment.
// If recovery secrets are defined, this function will return the encrypted recovery data.
func ManifestSet(ctx context.Context, endpoint string, trustedRoot *x509.Certificate, manifest []byte) (recoveryData map[string][]byte, err error) {
	client, err := rest.NewClient(endpoint, trustedRoot, nil)
	if err != nil {
		return nil, fmt.Errorf("setting up client: %w", err)
	}
	resp, err := client.Post(ctx, rest.ManifestEndpoint, rest.ContentJSON, bytes.NewReader(manifest))
	if err != nil {
		return nil, fmt.Errorf("sending manifest to Coordinator: %w", err)
	}

	if len(resp) > 0 {
		var response server.RecoveryDataResp
		if err := json.Unmarshal(resp, &response); err != nil {
			return nil, fmt.Errorf("unmarshalling Coordinator response: %w", err)
		}
		recoveryData = response.RecoverySecrets
	}

	return recoveryData, nil
}

// ManifestUpdateApply sets a manifest update for a MarbleRun deployment.
func ManifestUpdateApply(ctx context.Context, endpoint string, trustedRoot *x509.Certificate, updateManifest []byte, clientKeyPair *tls.Certificate) error {
	client, err := rest.NewClient(endpoint, trustedRoot, clientKeyPair)
	if err != nil {
		return fmt.Errorf("setting up client: %w", err)
	}
	_, err = client.Post(ctx, rest.UpdateEndpoint, rest.ContentJSON, bytes.NewReader(updateManifest))
	return err
}

// ManifestUpdateGet retrieves a pending manifest update of a MarbleRun deployment.
func ManifestUpdateGet(ctx context.Context, endpoint string, trustedRoot *x509.Certificate) (pendingManifest []byte, missingUsers []string, err error) {
	client, err := rest.NewClient(endpoint, trustedRoot, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("setting up client: %w", err)
	}
	resp, err := client.Get(ctx, rest.UpdateStatusEndpoint, http.NoBody)
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
func ManifestUpdateAcknowledge(ctx context.Context, endpoint string, trustedRoot *x509.Certificate, updateManifest []byte, clientKeyPair *tls.Certificate) (missingUsers []string, err error) {
	client, err := rest.NewClient(endpoint, trustedRoot, clientKeyPair)
	if err != nil {
		return nil, fmt.Errorf("setting up client: %w", err)
	}

	// Attempt to acknowledge the update using the v2 API first
	missingUsers, err = manifestUpdateAcknowledgeV2(ctx, client, updateManifest)
	if err != nil {
		// If the Coordinator does not support the v2 API, fall back to v1
		var notAllowedErr *rest.NotAllowedError
		if !errors.As(err, &notAllowedErr) {
			return nil, fmt.Errorf("sending manifest update acknowledgement: %w", err)
		}

		missingUsers, err = manifestUpdateAcknowledgeV1(ctx, client, updateManifest)
	}
	return missingUsers, err
}

// ManifestUpdateCancel cancels a pending manifest update of a MarbleRun deployment.
func ManifestUpdateCancel(ctx context.Context, endpoint string, trustedRoot *x509.Certificate, clientKeyPair *tls.Certificate) error {
	client, err := rest.NewClient(endpoint, trustedRoot, clientKeyPair)
	if err != nil {
		return fmt.Errorf("setting up client: %w", err)
	}

	// Attempt to cancel the update using the v2 API first
	_, err = client.Post(ctx, rest.V2API+rest.UpdateCancelEndpoint, "", http.NoBody)
	if err != nil {
		// If the Coordinator does not support the v2 API, fall back to v1
		var notAllowedErr *rest.NotAllowedError
		if !errors.As(err, &notAllowedErr) {
			return fmt.Errorf("sending manifest update cancel: %w", err)
		}
		_, err = client.Post(ctx, rest.UpdateCancelEndpoint, "", http.NoBody)

	}
	return err
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
	resp, err := client.Get(ctx, rest.SecretEndpoint, http.NoBody, query...)
	if err != nil {
		return nil, fmt.Errorf("retrieving secrets: %w", err)
	}

	secretMap := make(map[string]manifest.Secret, len(secrets))
	if err := json.Unmarshal(resp, &secretMap); err != nil {
		return nil, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}
	return secretMap, nil
}

// SecretSet sets secrets for a MarbleRun deployment.
func SecretSet(ctx context.Context, endpoint string, trustedRoot *x509.Certificate, clientKeyPair *tls.Certificate, secrets map[string]manifest.UserSecret) error {
	client, err := rest.NewClient(endpoint, trustedRoot, clientKeyPair)
	if err != nil {
		return fmt.Errorf("setting up client: %w", err)
	}

	secretDataJSON, err := json.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("marshalling secrets: %w", err)
	}
	_, err = client.Post(ctx, rest.SecretEndpoint, rest.ContentJSON, bytes.NewReader(secretDataJSON))
	return err
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

	signReq, err := json.Marshal(server.QuoteSignReq{SGXQuote: sgxQuote})
	if err != nil {
		return nil, tcbstatus.Unknown, fmt.Errorf("marshalling quote sign request: %w", err)
	}

	resp, err := client.Post(ctx, rest.V2API+rest.SignQuoteEndpoint, rest.ContentJSON, bytes.NewReader(signReq))
	if err != nil {
		return nil, tcbstatus.Unknown, fmt.Errorf("sending quote sign request: %w", err)
	}

	var response server.QuoteSignResp
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

	// Nonce is an optional, user-defined nonce to be included in the Coordinator's attestation statement.
	// If set, the Coordinator will generate an SGX quote over sha256(Coordinator_root_cert, Nonce).
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

// recoverV2 performs recovery of the Coordinator using the v2 API.
func recoverV2(ctx context.Context, client *rest.Client, recoverySecret []byte) (remaining int, err error) {
	recoverySecretJSON, err := json.Marshal(server.RecoveryV2Request{RecoverySecret: recoverySecret})
	if err != nil {
		return -1, err
	}

	resp, err := client.Post(ctx, rest.V2API+rest.RecoverEndpoint, rest.ContentJSON, bytes.NewReader(recoverySecretJSON))
	if err != nil {
		return -1, err
	}

	var response server.RecoveryV2Resp
	if err := json.Unmarshal(resp, &response); err != nil {
		return -1, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}
	return response.Remaining, nil
}

// recoverV1 performs recovery of the Coordinator using the legacy v1 API.
func recoverV1(ctx context.Context, client *rest.Client, recoverySecret []byte) (remaining int, err error) {
	resp, err := client.Post(ctx, rest.RecoverEndpoint, rest.ContentPlain, bytes.NewReader(recoverySecret))
	if err != nil {
		return -1, err
	}

	var response struct {
		Message string `json:"StatusMessage"`
	}
	if err := json.Unmarshal(resp, &response); err != nil {
		return -1, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}

	if response.Message == "Recovery successful." {
		return 0, nil
	}

	remainingStr, _, _ := strings.Cut(response.Message, ": ")
	remaining, err = strconv.Atoi(remainingStr)
	if err != nil {
		return -1, fmt.Errorf("parsing remaining recovery secrets: %w", err)
	}

	return remaining, nil
}

func manifestUpdateAcknowledgeV2(ctx context.Context, client *rest.Client, updateManifest []byte) (missingUsers []string, err error) {
	updateManifestJSON, err := json.Marshal(struct {
		Manifest []byte `json:"manifest"`
	}{
		Manifest: updateManifest,
	})
	if err != nil {
		return nil, err
	}

	resp, err := client.Post(ctx, rest.V2API+rest.UpdateStatusEndpoint, rest.ContentJSON, bytes.NewReader(updateManifestJSON))
	if err != nil {
		return nil, err
	}

	var response struct {
		MissingUsers []string `json:"missingUsers"`
	}
	if err := json.Unmarshal(resp, &response); err != nil {
		return nil, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}

	return response.MissingUsers, nil
}

func manifestUpdateAcknowledgeV1(ctx context.Context, client *rest.Client, updateManifest []byte) (missingUsers []string, err error) {
	resp, err := client.Post(ctx, rest.UpdateStatusEndpoint, rest.ContentJSON, bytes.NewReader(updateManifest))
	if err != nil {
		return nil, err
	}

	missing, _, _ := strings.Cut(string(resp), " ")
	if missing == "All" {
		return nil, nil
	}
	numMissing, err := strconv.Atoi(missing)
	if err != nil {
		return nil, fmt.Errorf("parsing number of missing users: %w", err)
	}

	for i := 0; i < numMissing; i++ {
		missingUsers = append(missingUsers, fmt.Sprintf("User%d", i))
	}

	return missingUsers, nil
}
