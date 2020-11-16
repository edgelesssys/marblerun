// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

const sealedDataFname string = "sealed_data"
const sealedKeyFname string = "sealed_key"

// Sealer is an interface for the Core object to seal information to the filesystem for persistence
type Sealer interface {
	Seal(data []byte) ([]byte, error)
	Unseal() ([]byte, error)
	GenerateNewEncryptionKey() error
	SetEncryptionKey(key []byte) error
}

// AESGCMSealer implements the Sealer interface using AES-GCM for confidentiallity and authentication
type AESGCMSealer struct {
	sealDir       string
	sealKey       []byte
	encryptionKey []byte
}

// NewAESGCMSealer creates and initializes a new AESGCMSealer object
func NewAESGCMSealer(sealDir string, sealKey []byte) *AESGCMSealer {
	return &AESGCMSealer{sealDir: sealDir, sealKey: sealKey}
}

// Unseal reads and decrypts stored information from the fs
func (s *AESGCMSealer) Unseal() ([]byte, error) {
	// load from fs
	sealedData, err := ioutil.ReadFile(s.getFname(sealedDataFname))

	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	// Decrypt generated encryption key with seal key, if needed
	if err = s.unsealEncryptionKey(); err != nil {
		return nil, err
	}

	// Decrypt data with the unsealed encryption key and return it
	return decrypt(sealedData, s.encryptionKey)
}

// Seal encrypts and stores information to the fs
func (s *AESGCMSealer) Seal(data []byte) ([]byte, error) {
	// If we don't have an AES key to encrypt the state, generate one
	if err := s.unsealEncryptionKey(); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if err := s.GenerateNewEncryptionKey(); err != nil {
			return nil, err
		}
	}

	// Encrypt data to seal with generated encryption key
	encryptedData, err := encrypt(data, s.encryptionKey)
	if err != nil {
		return nil, err
	}

	// store to fs
	if err := ioutil.WriteFile(s.getFname(sealedDataFname), encryptedData, 0600); err != nil {
		return nil, err
	}

	return s.encryptionKey, nil
}

func (s *AESGCMSealer) getFname(basename string) string {
	return filepath.Join(s.sealDir, basename)
}

func (s *AESGCMSealer) unsealEncryptionKey() error {
	if s.encryptionKey != nil {
		return nil
	}

	// Read from fs
	sealedKeyData, err := ioutil.ReadFile(s.getFname(sealedKeyFname))
	if err != nil {
		return err
	}

	// Decrypt stored encryption key with seal key
	encryptionKey, err := decrypt(sealedKeyData, s.sealKey)
	if err != nil {
		return err
	}

	// Restore encryption key
	s.encryptionKey = encryptionKey

	return nil
}

// GenerateNewEncryptionKey generates a random 128 Bit (16 Byte) key to encrypt the state
func (s *AESGCMSealer) GenerateNewEncryptionKey() error {
	encryptionKey := make([]byte, 16)

	_, err := rand.Read(encryptionKey)
	if err != nil {
		return err
	}

	return s.SetEncryptionKey(encryptionKey)
}

// SetEncryptionKey sets or restores an encryption key
func (s *AESGCMSealer) SetEncryptionKey(encryptionKey []byte) error {
	// If there already is an existing key file stored on disk, save it
	if sealedKeyData, err := ioutil.ReadFile(s.getFname(sealedKeyFname)); err == nil {
		t := time.Now()
		newFileName := s.getFname(sealedKeyFname) + "_" + t.Format("20060102150405") + ".bak"
		ioutil.WriteFile(newFileName, sealedKeyData, 0600)
	}

	// Encrypt encryption key with seal key
	encryptedKeyData, err := encrypt(encryptionKey, s.sealKey)
	if err != nil {
		return err
	}

	// Write the sealed encryption key to disk
	if err = ioutil.WriteFile(s.getFname(sealedKeyFname), encryptedKeyData, 0600); err != nil {
		return err
	}

	s.encryptionKey = encryptionKey

	return nil
}

func getCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	// Create cipher object with the given key
	aesgcm, err := getCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Encrypt data
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	return append(nonce, ciphertext...), nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	// Create cipher object with the given key
	aesgcm, err := getCipher(key)
	if err != nil {
		return nil, err
	}

	// Split ciphertext into nonce & actual data
	nonce, encryptedData := ciphertext[:aesgcm.NonceSize()], ciphertext[aesgcm.NonceSize():]

	// Decrypt data
	plaintext, err := aesgcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// MockSealer is a mockup sealer
type MockSealer struct {
	data []byte
}

// Unseal implements the Sealer interface
func (s *MockSealer) Unseal() ([]byte, error) {
	return s.data, nil
}

// Seal implements the Sealer interface
func (s *MockSealer) Seal(data []byte) ([]byte, error) {
	s.data = data
	return []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, nil
}

// SetEncryptionKey implements the Sealer interface
func (s *MockSealer) SetEncryptionKey(key []byte) error {
	return nil
}

// GenerateNewEncryptionKey implements the Sealer interface
func (s *MockSealer) GenerateNewEncryptionKey() error {
	return nil
}
