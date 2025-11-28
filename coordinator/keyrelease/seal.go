/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package keyrelease

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/edgelesssys/marblerun/coordinator/seal"
)

// SealEncryptionKey seals the encryption key, and, if enabled, wraps it using the HSM key from Azure Key Vault.
func (k *KeyReleaser) SealEncryptionKey(additionalData []byte, mode seal.Mode) ([]byte, error) {
	encryptedKey, err := k.Sealer.SealEncryptionKey(additionalData, mode)
	if err != nil {
		return nil, err
	}

	if k.enabled {
		if k.hsmSealingKey == nil {
			hsmSealingKey, err := k.getKey(context.Background())
			if err != nil {
				return nil, err
			}
			k.hsmSealingKey = hsmSealingKey
		}

		// TODO: replace with symmetric key sealing
		priv, err := x509.ParsePKCS8PrivateKey(k.hsmSealingKey)
		if err != nil {
			return nil, err
		}
		rsaPriv, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("expected RSA key")
		}
		encryptedKey, err = rsa.EncryptOAEP(sha256.New(), nil, &rsaPriv.PublicKey, encryptedKey, nil)
		if err != nil {
			return nil, err
		}
	}

	return encryptedKey, nil
}

// UnsealEncryptionKey unseals the encryption key, and, if enabled, unwraps it using the HSM key from Azure Key Vault.
func (k *KeyReleaser) UnsealEncryptionKey(encryptedKey, additionalData []byte) ([]byte, error) {
	if k.enabled {
		if k.hsmSealingKey == nil {
			hsmSealingKey, err := k.getKey(context.Background())
			if err != nil {
				return nil, err
			}
			k.hsmSealingKey = hsmSealingKey
		}

		// TODO: replace with symmetric key sealing
		priv, err := x509.ParsePKCS8PrivateKey(k.hsmSealingKey)
		if err != nil {
			return nil, err
		}
		rsaPriv, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("expected RSA key")
		}
		encryptedKey, err = rsa.DecryptOAEP(sha256.New(), nil, rsaPriv, encryptedKey, nil)
		if err != nil {
			return nil, err
		}
	}

	return k.Sealer.UnsealEncryptionKey(encryptedKey, additionalData)
}
