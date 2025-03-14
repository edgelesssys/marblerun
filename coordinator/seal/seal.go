/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// Package seal implements sealing operations for the Coordinator.
package seal

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/edgelesssys/ego/ecrypto"
	"go.uber.org/zap"
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

// Sealer handles encryption and decryption of data.
type Sealer interface {
	// Seal encrypts data using the encryption key of the Sealer.
	Seal(unencryptedData []byte, toBeEncrypted []byte) (encryptedData []byte, err error)
	// Unseal decrypts the given data and returns the plain text, as well as the unencrypted metadata.
	Unseal(encryptedData []byte) (unencryptedData []byte, decryptedData []byte, err error)
	// UnsealWithKey decrypts the given data with the provided encryption key and returns the plain text,
	// as well as the unencrypted metadata.
	UnsealWithKey(encryptedData, encryptionKey []byte) (unencryptedData []byte, decryptedData []byte, err error)
	// SealEncryptionKey seals an encryption key using the sealer.
	SealEncryptionKey(additionalData []byte, mode Mode) (encryptedKey []byte, err error)
	// SetEncryptionKey sets the encryption key of the sealer.
	SetEncryptionKey(key []byte)
	// UnsealEncryptionKey decrypts an encrypted key.
	UnsealEncryptionKey(encryptedKey, additionalData []byte) ([]byte, error)
}

// AESGCMSealer implements the Sealer interface using AES-GCM for confidentiality and authentication.
type AESGCMSealer struct {
	encryptionKey []byte
	log           *zap.Logger
}

// NewAESGCMSealer creates and initializes a new AESGCMSealer object.
func NewAESGCMSealer(log *zap.Logger) *AESGCMSealer {
	return &AESGCMSealer{
		log: log,
	}
}

// Unseal decrypts sealedData and returns the decrypted data,
// as well as the prefixed unencrypted metadata of the cipher text.
func (s *AESGCMSealer) Unseal(sealedData []byte) ([]byte, []byte, error) {
	return s.unseal(sealedData, s.encryptionKey)
}

// UnsealWithKey decrypts sealedData with the given encryption key and returns the decrypted data,
// as well as the prefixed unencrypted metadata of the cipher text.
func (s *AESGCMSealer) UnsealWithKey(sealedData, encryptionKey []byte) ([]byte, []byte, error) {
	return s.unseal(sealedData, encryptionKey)
}

// Seal encrypts and stores information to the fs.
func (s *AESGCMSealer) Seal(unencryptedData []byte, toBeEncrypted []byte) ([]byte, error) {
	return sealData(unencryptedData, toBeEncrypted, s.encryptionKey, s.log)
}

// SealEncryptionKey seals the sealer's encryption key with the selected enclave key.
func (s *AESGCMSealer) SealEncryptionKey(additionalData []byte, mode Mode) ([]byte, error) {
	switch mode {
	case ModeProductKey:
		s.log.Debug("Sealing encryption key with product key")
		return ecrypto.SealWithProductKey(s.encryptionKey, additionalData)
	case ModeUniqueKey:
		s.log.Debug("Sealing encryption key with unique key")
		return ecrypto.SealWithUniqueKey(s.encryptionKey, additionalData)
	}
	return nil, errors.New("sealing is disabled")
}

// SetEncryptionKey sets the encryption key of the Sealer.
func (s *AESGCMSealer) SetEncryptionKey(encryptionKey []byte) {
	s.encryptionKey = encryptionKey
}

// UnsealEncryptionKey unseals the encryption key.
func (s *AESGCMSealer) UnsealEncryptionKey(encryptedKey, additionalData []byte) ([]byte, error) {
	// Decrypt stored encryption key with seal key
	encryptionKey, err := ecrypto.Unseal(encryptedKey, additionalData)
	if err != nil {
		return nil, err
	}

	return encryptionKey, nil
}

func (s *AESGCMSealer) unseal(sealedData, encryptionKey []byte) ([]byte, []byte, error) {
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

// GenerateEncryptionKey generates a new random 16 byte encryption key.
func GenerateEncryptionKey() ([]byte, error) {
	encryptionKey := make([]byte, 16)

	_, err := rand.Read(encryptionKey)
	if err != nil {
		return nil, err
	}

	return encryptionKey, nil
}

// prepareCipherText validates format of the given sealed data.
// It returns the unencrypted metadata and the cipher text.
func prepareCipherText(sealedData []byte, log *zap.Logger) (unencryptedData []byte, cipherText []byte, err error) {
	log.Debug("Preparing cipher text for unsealing", zap.Int("sealedDataLength", len(sealedData)))
	if len(sealedData) <= 4 {
		return nil, nil, errors.New("sealed state is missing data")
	}

	// Retrieve recovery secret hash map
	encodedUnencryptedDataLength := binary.LittleEndian.Uint32(sealedData[:4])
	log.Debug("Checking encoded unencrypted data", zap.Uint32("length", encodedUnencryptedDataLength))

	// Check if we do not go out of bounds
	if 4+encodedUnencryptedDataLength > uint32(len(sealedData)) {
		return nil, nil, errors.New("sealed state is corrupted, embedded length does not fit the data")
	}

	if encodedUnencryptedDataLength != 0 {
		unencryptedData = sealedData[4 : 4+encodedUnencryptedDataLength]
	}
	cipherText = sealedData[4+encodedUnencryptedDataLength:]
	log.Debug("Cipher text is ready for unsealing", zap.Binary("unencryptedData", unencryptedData))

	return unencryptedData, cipherText, nil
}

// sealData encrypts data and seals it with the given key.
// It returns the encrypted data prefixed with the unencrypted data and it's length.
//
// Format: uint32(littleEndian(len(unencryptedData))) || unencryptedData || encrypt(toBeEncrypted).
func sealData(unencryptedData, toBeEncrypted, encryptionKey []byte, log *zap.Logger) ([]byte, error) {
	log.Debug("Preparing to seal data", zap.Binary("unencryptedData", unencryptedData))
	if encryptionKey == nil {
		return nil, fmt.Errorf("encrypting data: %w", ErrMissingEncryptionKey)
	}

	// Encrypt data to seal with generated encryption key
	encryptedData, err := ecrypto.Encrypt(toBeEncrypted, encryptionKey, nil)
	if err != nil {
		return nil, fmt.Errorf("encrypting data: %w", err)
	}

	unencryptedDataLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(unencryptedDataLength, uint32(len(unencryptedData)))
	unencryptedData = append(unencryptedDataLength, unencryptedData...)

	// Append unencrypted data with encrypted data
	encryptedData = append(unencryptedData, encryptedData...)

	log.Debug("Data sealing completed")
	return encryptedData, nil
}
