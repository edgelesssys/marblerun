/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package keyrelease

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/edgelesssys/ego/enclave"
	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/distributor"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	dstore "github.com/edgelesssys/marblerun/coordinator/store/distributed"
	"github.com/edgelesssys/marblerun/util"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/tink-crypto/tink-go/v2/kwp/subtle"
	"go.uber.org/zap"
)

const (
	wrappingKeySize = 4096
)

type distributedSealer interface {
	dstore.Sealer
	distributor.KeyGenerator
}

// KeyReleaser releases keys from an Azure Key Vault using Secure Key Release.
type KeyReleaser struct {
	distributedSealer

	enabled       bool
	hsmSealingKey []byte
	keyName       string
	keyVersion    string
	maaURL        string
	client        *azkeys.Client

	log *zap.Logger
}

// New creates a new [KeyReleaser] with credentials from environment variables.
func New(sealer seal.Sealer, log *zap.Logger) (*KeyReleaser, error) {
	if err := os.Setenv(constants.EnvAzureClientID, os.Getenv("EDG_"+constants.EnvAzureClientID)); err != nil {
		return nil, err
	}
	if err := os.Setenv(constants.EnvAzureTenantID, os.Getenv("EDG_"+constants.EnvAzureTenantID)); err != nil {
		return nil, err
	}
	if err := os.Setenv(constants.EnvAzureClientSecret, os.Getenv("EDG_"+constants.EnvAzureClientSecret)); err != nil {
		return nil, err
	}

	vaultURL := os.Getenv(constants.EnvHSMVaultURL)
	keyName := os.Getenv(constants.EnvHSMKeyName)
	keyVersion := os.Getenv(constants.EnvHSMKeyVersion)
	maaURL := util.Getenv(constants.EnvMAAURL, "https://shareduks.uks.attest.azure.net") // fallback to uk-south attestation provider

	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: insecureClient(), // Skip TLS verification. There is no need for a trusted connection
		},
	})
	if err != nil {
		return nil, err
	}

	client, err := azkeys.NewClient(vaultURL, cred, &azkeys.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: insecureClient(), // Skip TLS verification. There is no need for a trusted connection
		},
	})
	if err != nil {
		return nil, err
	}

	castSealer, ok := sealer.(distributedSealer)
	if !ok {
		castSealer = &stubDistributedSealer{
			Sealer: sealer,
			log:    log,
		}
	}

	return &KeyReleaser{
		distributedSealer: castSealer,
		keyName:           keyName,
		keyVersion:        keyVersion,
		maaURL:            maaURL,
		client:            client,
		enabled:           false,
		log:               log,
	}, nil
}

// Enable the wrapping and unwrapping of keys using an HSM key from Azure Key Vault.
func (k *KeyReleaser) Enable() {
	k.enabled = true
}

// requestKey requests the release of a key from Azure Key Vault by providing
// an Azure attestation token. The policy on the key must allow release based
// on the claims in the provided token.
func (k *KeyReleaser) requestKey(ctx context.Context) error {
	k.log.Debug("Creating wrapping key")
	wrappingKey, jwk, err := createWrappingKey()
	if err != nil {
		return err
	}

	// The key vault expects the token to be created over a JWK Set containing an RSA key.
	// The key will be used by the vault to encrypt the released key before sending it to the caller.
	k.log.Debug("Requesting Azure attestation token")
	attestationToken, err := enclave.CreateAzureAttestationToken(jwk, k.maaURL)
	if err != nil {
		return fmt.Errorf("creating Azure attestation token: %w", err)
	}

	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	// Request key release
	k.log.Debug("Requesting key release from Azure Key Vault")
	res, err := k.client.Release(ctx, k.keyName, k.keyVersion, azkeys.ReleaseParameters{
		TargetAttestationToken: &attestationToken,
		Enc:                    toPtr(azkeys.KeyEncryptionAlgorithmRSAAESKEYWRAP384),
		Nonce:                  toPtr(string(nonce)),
	}, nil)
	if err != nil {
		return fmt.Errorf("requesting key release: %w", err)
	}

	k.log.Debug("Parsing released key")
	ciphertext, err := parseCiphertextFromResponse(*res.Value)
	if err != nil {
		return fmt.Errorf("parsing released key: %w", err)
	}

	// Extract the key encryption key (KEK) and the encrypted key (the _actual_ key) from the ciphertext
	encryptedKEK := make([]byte, wrappingKeySize/8)
	copy(encryptedKEK, ciphertext[:wrappingKeySize/8])
	encryptedKey := make([]byte, len(ciphertext)-wrappingKeySize/8)
	copy(encryptedKey, ciphertext[wrappingKeySize/8:])

	// The KEK was encrypted using the wrapping key we provided earlier.
	k.log.Debug("Decrypting KEK with wrapping key")
	kek, err := rsa.DecryptOAEP(sha512.New384(), nil, wrappingKey, encryptedKEK, nil)
	if err != nil {
		return fmt.Errorf("decrypting KEK: %w", err)
	}

	// The actual key is encrypted using AES key wrapping as defined in https://www.rfc-editor.org/rfc/rfc5649.html
	// using the KEK
	k.log.Debug("Decrypting released key")
	kwp, err := subtle.NewKWP(kek)
	if err != nil {
		return fmt.Errorf("creating KWP: %w", err)
	}
	releasedKey, err := kwp.Unwrap(encryptedKey)
	if err != nil {
		return fmt.Errorf("unwrapping encrypted key: %w", err)
	}

	k.hsmSealingKey = releasedKey
	return nil
}

// createWrappingKey generates a wrapping key and its JWK representation.
func createWrappingKey() (*rsa.PrivateKey, []byte, error) {
	wrappingKey, err := rsa.GenerateKey(rand.Reader, wrappingKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("generating wrapping key: %w", err)
	}

	jwKey, err := jwk.Import(&wrappingKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("importing wrapping key as jwk: %w", err)
	}
	if err = jwk.AssignKeyID(jwKey); err != nil {
		return nil, nil, fmt.Errorf("assigning key ID to jwk: %w", err)
	}
	if err = jwKey.Set("key_ops", "encrypt"); err != nil {
		return nil, nil, fmt.Errorf("setting key operations to jwk: %w", err)
	}

	jwkSet := jwk.NewSet()
	if err := jwkSet.AddKey(jwKey); err != nil {
		return nil, nil, fmt.Errorf("adding jwk to jwk set: %w", err)
	}

	jwkSetBytes, err := json.Marshal(jwkSet)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling jwk set: %w", err)
	}
	return wrappingKey, jwkSetBytes, nil
}

// parseCiphertextFromResponse extracts the wrapped key from the key vault response.
func parseCiphertextFromResponse(response string) ([]byte, error) {
	// The response is a JWS containing a JSON payload with the key material.
	// We don't care about deep verification of the JWS since the key in the payload
	// is encrypted with a an asymmetric key only we possess.
	// Further, even if the key is "malicious", e.g. known by an attacker,
	// the security of the MarbleRun state won't be negatively impacted in comparison
	// to not using SKR at all to seal the state. This is because we perform double sealing.
	// I.e. we seal the DEK with the SGX enclave key and then seal this again with the SKR-released key.
	jws, err := jws.Parse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("parsing JWS: %w", err)
	}

	var skrResponse struct {
		Response struct {
			Key struct {
				Key struct {
					KeyHSM string `json:"key_hsm"`
				} `json:"key"`
			} `json:"key"`
		} `json:"response"`
	}
	if err = json.Unmarshal(jws.Payload(), &skrResponse); err != nil {
		return nil, fmt.Errorf("unmarshalling JWS payload: %w", err)
	}
	keyHSMBytes, err := base64.RawURLEncoding.DecodeString(skrResponse.Response.Key.Key.KeyHSM)
	if err != nil {
		return nil, fmt.Errorf("decoding key_hsm: %w", err)
	}
	var keyHSM struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err = json.Unmarshal(keyHSMBytes, &keyHSM); err != nil {
		return nil, fmt.Errorf("unmarshalling key_hsm: %w", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(keyHSM.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decoding key_hsm ciphertext: %w", err)
	}

	return ciphertext, nil
}

// insecureClient returns an HTTP client that skips TLS certificate verification.
// This is used to bypass the fact that the enclave does not have a set of Root CAs.
func insecureClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func toPtr[T any](v T) *T {
	return &v
}

type stubDistributedSealer struct {
	seal.Sealer
	log *zap.Logger
}

func (s *stubDistributedSealer) SealKEK(context.Context, seal.Mode) error {
	s.log.Error("Stub distributed sealer: SealKEK called")
	return errors.New("unsupported function called")
}

func (s *stubDistributedSealer) SetSealMode(seal.Mode) {
	s.log.Error("Stub distributed sealer: SetSealMode called")
}

func (s *stubDistributedSealer) ExportKeyEncryptionKey(context.Context) ([]byte, error) {
	s.log.Error("Stub distributed sealer: ExportKeyEncryptionKey called")
	return nil, errors.New("unsupported function called")
}

func (s *stubDistributedSealer) SetKeyEncryptionKey(context.Context, []byte) error {
	s.log.Error("Stub distributed sealer: SetKeyEncryptionKey called")
	return errors.New("unsupported function called")
}
