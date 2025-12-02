/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package keyrelease

import (
	"bytes"
	"context"

	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/marblerun/coordinator/seal"
)

var hsmSealedPrefix = []byte("HSM_SEALED")

// SealEncryptionKey seals the encryption key, and, if enabled, wraps it using an HSM key from Azure Key Vault.
func (k *KeyReleaser) SealEncryptionKey(additionalData []byte, mode seal.Mode) ([]byte, error) {
	encryptedKey, err := k.distributedSealer.SealEncryptionKey(additionalData, mode)
	if err != nil {
		return nil, err
	}

	if !k.enabled {
		return encryptedKey, nil
	}

	k.log.Debug("Wrapping encrypted key with HSM key")
	if k.hsmSealingKey == nil {
		if err := k.requestKey(context.Background()); err != nil {
			return nil, err
		}
	}

	hsmWrappedKey, err := ecrypto.Encrypt(encryptedKey, k.hsmSealingKey, additionalData)
	if err != nil {
		return nil, err
	}
	return append(hsmSealedPrefix, hsmWrappedKey...), nil
}

// UnsealEncryptionKey unseals the encryption key, and, if needed, unwraps it using an HSM key from Azure Key Vault.
func (k *KeyReleaser) UnsealEncryptionKey(encryptedKey, additionalData []byte) ([]byte, error) {
	if hsmWrappedKey, ok := bytes.CutPrefix(encryptedKey, hsmSealedPrefix); ok {
		k.log.Debug("Unwrapping encrypted key with HSM key")
		if k.hsmSealingKey == nil {
			if err := k.requestKey(context.Background()); err != nil {
				return nil, err
			}
		}

		var err error
		encryptedKey, err = ecrypto.Decrypt(hsmWrappedKey, k.hsmSealingKey, additionalData)
		if err != nil {
			return nil, err
		}
	}

	return k.distributedSealer.UnsealEncryptionKey(encryptedKey, additionalData)
}
