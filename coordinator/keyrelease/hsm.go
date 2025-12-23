//go:build !fakehsm

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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/edgelesssys/ego/enclave"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/tink-crypto/tink-go/v2/kwp/subtle"
)

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
		Algorithm:              toPtr(azkeys.KeyEncryptionAlgorithmRSAAESKEYWRAP384),
		Nonce:                  toPtr(string(nonce)),
	}, nil)
	if err != nil {
		return fmt.Errorf("requesting key release: %w", err)
	}

	k.log.Debug("Parsing released key")
	ciphertext, err := parseCiphertextFromResponse(*res.Value, k.vaultURL)
	if err != nil {
		return fmt.Errorf("parsing released key: %w", err)
	}

	// Extract the key encryption key (KEK) and the encrypted key (the _actual_ key) from the ciphertext
	encryptedKEK, encryptedKey := ciphertext[:wrappingKeySize/8], ciphertext[wrappingKeySize/8:]

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
func parseCiphertextFromResponse(response, vaultURL string) ([]byte, error) {
	// Extract header from JWS response
	headerString, _, _ := strings.Cut(response, ".")
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerString)
	if err != nil {
		return nil, fmt.Errorf("decoding header: %w", err)
	}
	var header jwsHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("unmarshalling header: %w", err)
	}
	if err := header.verify(vaultURL); err != nil {
		return nil, fmt.Errorf("verifying jws header: %w", err)
	}

	// Verify JWS signature and extract payload
	payload, err := jws.Verify([]byte(response), jws.WithKey(header.Alg, header.CertChain[0].PublicKey))
	if err != nil {
		return nil, fmt.Errorf("verifying JWS: %w", err)
	}

	// Parse payload to extract the wrapped key
	var skrResponse struct {
		Response struct {
			Key struct {
				Key struct {
					KeyHSM string `json:"key_hsm"`
				} `json:"key"`
			} `json:"key"`
		} `json:"response"`
	}
	if err = json.Unmarshal(payload, &skrResponse); err != nil {
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

type jwsHeader struct {
	Alg       jwa.SignatureAlgorithm `json:"alg"`
	CertChain []*x509.Certificate    `json:"x5c"`
}

func (h *jwsHeader) UnmarshalJSON(data []byte) error {
	var aux struct {
		Alg string   `json:"alg"`
		X5C [][]byte `json:"x5c"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	alg, ok := jwa.LookupSignatureAlgorithm(aux.Alg)
	if !ok {
		return fmt.Errorf("unsupported JWS alg: %s", aux.Alg)
	}
	h.Alg = alg

	h.CertChain = make([]*x509.Certificate, len(aux.X5C))
	for i, certBytes := range aux.X5C {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return fmt.Errorf("parsing certificate from jws header: %w", err)
		}
		h.CertChain[i] = cert
	}
	if len(h.CertChain) == 0 {
		return errors.New("no certificates in jws header")
	}
	return nil
}

func (h jwsHeader) verify(vaultURL string) error {
	leafCert := h.CertChain[0]

	intermediates := x509.NewCertPool()
	for _, cert := range h.CertChain[1:] {
		intermediates.AddCert(cert)
	}

	url, err := url.Parse(vaultURL)
	if err != nil {
		return fmt.Errorf("parsing vault url: %w", err)
	}
	_, err = leafCert.Verify(x509.VerifyOptions{Roots: rootCerts, Intermediates: intermediates, DNSName: url.Hostname()})
	return err
}

func toPtr[T any](v T) *T {
	return &v
}
