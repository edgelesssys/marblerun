// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package seal implements sealing operations for the Coordinator.
package seal

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/edgelesssys/ego/ecrypto"
)

// EncryptionKeyError occurs if the encryption key cannot be unsealed.
type EncryptionKeyError struct {
	Err error
}

func (e *EncryptionKeyError) Error() string {
	return fmt.Sprintf("cannot unseal encryption key: %s", e.Err)
}

func (e *EncryptionKeyError) Unwrap() error {
	return e.Err
}

// ErrMissingEncryptionKey occurs if the encryption key is not set.
var ErrMissingEncryptionKey = errors.New("encryption key not set")

// Sealer is an interface for the Core object to seal information to the filesystem for persistence.
type Sealer interface {
	Seal(unencryptedData []byte, toBeEncrypted []byte) (encryptedData []byte, err error)
	Unseal(encryptedData []byte) (unencryptedData []byte, decryptedData []byte, err error)
	SetEncryptionKey(key []byte) (encryptedKey []byte, err error)
	UnsealEncryptionKey(encryptedKey []byte) ([]byte, error)
}

// AESGCMSealer implements the Sealer interface using AES-GCM for confidentiality and authentication.
type AESGCMSealer struct {
	encryptionKey []byte
}

// NewAESGCMSealer creates and initializes a new AESGCMSealer object.
func NewAESGCMSealer() *AESGCMSealer {
	return &AESGCMSealer{}
}

// Unseal reads and decrypts stored information from the fs.
func (s *AESGCMSealer) Unseal(sealedData []byte) ([]byte, []byte, error) {
	return unsealData(sealedData, s.encryptionKey)
}

// Seal encrypts and stores information to the fs.
func (s *AESGCMSealer) Seal(unencryptedData []byte, toBeEncrypted []byte) ([]byte, error) {
	return sealData(unencryptedData, toBeEncrypted, s.encryptionKey)
}

// SetEncryptionKey sets or restores an encryption key.
func (s *AESGCMSealer) SetEncryptionKey(encryptionKey []byte) ([]byte, error) {
	// Encrypt encryption key with seal key
	encryptedKeyData, err := ecrypto.SealWithProductKey(encryptionKey, nil)
	if err != nil {
		return nil, err
	}

	s.encryptionKey = encryptionKey

	return encryptedKeyData, nil
}

// UnsealEncryptionKey unseals the encryption key using the enclave's product key.
func (s *AESGCMSealer) UnsealEncryptionKey(encryptedKey []byte) ([]byte, error) {
	// Decrypt stored encryption key with seal key
	encryptionKey, err := ecrypto.Unseal(encryptedKey, nil)
	if err != nil {
		return nil, &EncryptionKeyError{Err: err}
	}

	return encryptionKey, nil
}

// GenerateEncryptionKey generates a new random 16 byte encryption key.
func GenerateEncryptionKey() ([]byte, error) {
	encryptionKey := make([]byte, 16)

	_, err := rand.Read(encryptionKey)
	if err != nil {
		return nil, err
	}

	return encryptionKey, nil
}

// unsealData decrypts the sealed data using the given key.
// It returns the unencrypted metadata and the decrypted data.
func unsealData(sealedData, encryptionKey []byte) (unencryptedData []byte, decryptedData []byte, err error) {
	if len(sealedData) <= 4 {
		return nil, nil, errors.New("sealed state is missing data")
	}

	// Retrieve recovery secret hash map
	encodedUnencryptDataLength := binary.LittleEndian.Uint32(sealedData[:4])

	// Check if we do not go out of bounds
	if 4+encodedUnencryptDataLength > uint32(len(sealedData)) {
		return nil, nil, errors.New("sealed state is corrupted, embedded length does not fit the data")
	}

	if encodedUnencryptDataLength != 0 {
		unencryptedData = sealedData[4 : 4+encodedUnencryptDataLength]
	}
	ciphertext := sealedData[4+encodedUnencryptDataLength:]

	if encryptionKey == nil {
		return unencryptedData, nil, ErrMissingEncryptionKey
	}

	// Decrypt data with the unsealed encryption key and return it
	decryptedData, err = ecrypto.Decrypt(ciphertext, encryptionKey, nil)
	if err != nil {
		return unencryptedData, nil, err
	}

	return unencryptedData, decryptedData, nil
}

// sealData encrypts data and seals it with the given key.
// It returns the encrypted data prefixed with the unencrypted data and it's length.
func sealData(unencryptedData, toBeEncrypted, encryptionKey []byte) ([]byte, error) {
	if encryptionKey == nil {
		return nil, ErrMissingEncryptionKey
	}

	// Encrypt data to seal with generated encryption key
	encryptedData, err := ecrypto.Encrypt(toBeEncrypted, encryptionKey, nil)
	if err != nil {
		return nil, err
	}

	unencryptDataLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(unencryptDataLength, uint32(len(unencryptedData)))
	unencryptedData = append(unencryptDataLength, unencryptedData...)

	// Append unencrypted data with encrypted data
	encryptedData = append(unencryptedData, encryptedData...)

	return encryptedData, nil
}
