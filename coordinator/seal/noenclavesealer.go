// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package seal

import (
	"fmt"

	"github.com/edgelesssys/ego/ecrypto"
)

// NoEnclaveSealer is a sealer for a -noenclave instance and performs encryption with a fixed key.
type NoEnclaveSealer struct {
	encryptionKey []byte
}

// NewNoEnclaveSealer creates and initializes a new NoEnclaveSealer object.
func NewNoEnclaveSealer() *NoEnclaveSealer {
	return &NoEnclaveSealer{}
}

// Unseal decrypts sealedData and returns the decrypted data,
// as well as the prefixed unencrypted metadata of the cipher text.
func (s *NoEnclaveSealer) Unseal(sealedData []byte) ([]byte, []byte, error) {
	unencryptedData, cipherText, err := prepareCipherText(sealedData)
	if err != nil {
		return unencryptedData, nil, err
	}

	if s.encryptionKey == nil {
		return unencryptedData, nil, fmt.Errorf("decrypting sealed data: %w", ErrMissingEncryptionKey)
	}

	// Decrypt data with the unsealed encryption key and return it
	decryptedData, err := ecrypto.Decrypt(cipherText, s.encryptionKey, nil)
	if err != nil {
		return unencryptedData, nil, fmt.Errorf("decrypting sealed data: %w", err)
	}

	return unencryptedData, decryptedData, nil
}

// Seal encrypts the given data using the sealer's key.
func (s *NoEnclaveSealer) Seal(unencryptedData []byte, toBeEncrypted []byte) ([]byte, error) {
	return sealData(unencryptedData, toBeEncrypted, s.encryptionKey)
}

// SealEncryptionKey implements the Sealer interface.
// Since the NoEnclaveSealer does not support sealing with an enclave key, it returns the key as is.
func (s *NoEnclaveSealer) SealEncryptionKey(key []byte) ([]byte, error) {
	return key, nil
}

// SetEncryptionKey implements the Sealer interface.
func (s *NoEnclaveSealer) SetEncryptionKey(key []byte) {
	s.encryptionKey = key
}

// UnsealEncryptionKey implements the Sealer interface.
func (s *NoEnclaveSealer) UnsealEncryptionKey(key []byte) ([]byte, error) {
	return key, nil
}
