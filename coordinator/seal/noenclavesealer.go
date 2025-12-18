/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package seal

import (
	"fmt"

	"github.com/edgelesssys/ego/ecrypto"
	"go.uber.org/zap"
)

// NoEnclaveSealer is a sealer for a -noenclave instance and performs encryption with a fixed key.
type NoEnclaveSealer struct {
	encryptionKey    []byte
	oldEncryptionKey []byte
	log              *zap.Logger
}

// NewNoEnclaveSealer creates and initializes a new NoEnclaveSealer object.
func NewNoEnclaveSealer(log *zap.Logger) *NoEnclaveSealer {
	return &NoEnclaveSealer{
		log: log,
	}
}

// Unseal decrypts sealedData and returns the decrypted data,
// as well as the prefixed unencrypted metadata of the cipher text.
func (s *NoEnclaveSealer) Unseal(sealedData []byte) ([]byte, []byte, error) {
	return s.unseal(sealedData, s.encryptionKey)
}

// UnsealWithKey decrypts sealedData using the given encryptionKey and returns the decrypted data,
// as well as the prefixed unencrypted metadata of the cipher text.
func (s *NoEnclaveSealer) UnsealWithKey(sealedData, encryptionKey []byte) ([]byte, []byte, error) {
	return s.unseal(sealedData, encryptionKey)
}

// Seal encrypts the given data using the sealer's key.
func (s *NoEnclaveSealer) Seal(unencryptedData []byte, toBeEncrypted []byte) ([]byte, error) {
	return sealData(unencryptedData, toBeEncrypted, s.encryptionKey, s.log)
}

// SealEncryptionKey implements the Sealer interface.
// Since the NoEnclaveSealer does not support sealing with an enclave key, it returns the key as is.
func (s *NoEnclaveSealer) SealEncryptionKey(_ []byte, _ Mode) ([]byte, error) {
	return s.encryptionKey, nil
}

// SetEncryptionKey implements the Sealer interface.
func (s *NoEnclaveSealer) SetEncryptionKey(key []byte) {
	s.oldEncryptionKey = s.encryptionKey
	s.encryptionKey = key
}

// ResetEncryptionKey implements the Sealer interface.
func (s *NoEnclaveSealer) ResetEncryptionKey() {
	s.encryptionKey = s.oldEncryptionKey
}

// UnsealEncryptionKey implements the Sealer interface.
func (s *NoEnclaveSealer) UnsealEncryptionKey(key, _ []byte) ([]byte, error) {
	return key, nil
}

func (s *NoEnclaveSealer) unseal(sealedData, encryptionKey []byte) ([]byte, []byte, error) {
	unencryptedData, cipherText, err := prepareCipherText(sealedData, s.log)
	if err != nil {
		return unencryptedData, nil, err
	}

	if encryptionKey == nil {
		return unencryptedData, nil, fmt.Errorf("decrypting sealed data: %w", ErrMissingEncryptionKey)
	}

	// Decrypt data with the unsealed encryption key and return it
	decryptedData, err := ecrypto.Decrypt(cipherText, encryptionKey, nil)
	if err != nil {
		return unencryptedData, nil, fmt.Errorf("decrypting sealed data: %w", err)
	}

	return unencryptedData, decryptedData, nil
}
