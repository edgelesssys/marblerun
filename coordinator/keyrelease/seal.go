/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package keyrelease

import (
	"bytes"
	"context"
	"fmt"

	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/marblerun/coordinator/seal"
)

// HSMSealedPrefix is the prefix added to keys sealed with an HSM key.
var HSMSealedPrefix = []byte("HSM_SEALED")

// SealEncryptionKey seals the encryption key, and, if enabled, seals it again using an HSM key from Azure Key Vault.
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

	hsmWrappedKey, err := ecrypto.Encrypt(encryptedKey, k.hsmSealingKey, nil)
	if err != nil {
		return nil, fmt.Errorf("encrypting with HSM key: %w", err)
	}
	return append(HSMSealedPrefix, hsmWrappedKey...), nil
}

// UnsealEncryptionKey unseals an encryption key using an HSM key from Azure Key Vault, and then unseals the encryption key.
func (k *KeyReleaser) UnsealEncryptionKey(encryptedKey, additionalData []byte) ([]byte, error) {
	if hsmWrappedKey, ok := bytes.CutPrefix(encryptedKey, HSMSealedPrefix); ok {
		k.log.Debug("Unwrapping encrypted key with HSM key")
		if k.hsmSealingKey == nil {
			if err := k.requestKey(context.Background()); err != nil {
				return nil, err
			}
		}

		var err error
		encryptedKey, err = ecrypto.Decrypt(hsmWrappedKey, k.hsmSealingKey, nil)
		if err != nil {
			return nil, fmt.Errorf("decrypting HSM wrapped key: %w", err)
		}
	}

	return k.distributedSealer.UnsealEncryptionKey(encryptedKey, additionalData)
}
