// Copyright (c) Edgeless Systems GmbH.
// Licensed under the MIT License.

package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io/ioutil"
	"os"
	"path/filepath"
)

const sealedDataFname string = "sealed_data"
const sealedKeyFname string = "sealed_key"

// Sealer is an interface for the Core object to seal information to the filesystem for persistence
type Sealer interface {
	Seal(data []byte) ([]byte, error)
	Unseal() ([]byte, error)
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
	sealedData, err := ioutil.ReadFile(s.getFname("data"))
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	if err = s.unsealEncryptionKey(); err != nil {
		return nil, err
	}

	// Use encryption key to decrypt state
	aesgcm, err := getCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}

	// decrypt
	nonce, encData := sealedData[:aesgcm.NonceSize()], sealedData[aesgcm.NonceSize():]
	data, err := aesgcm.Open(nil, nonce, encData, nil)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// Seal encrypts and stores information to the fs
func (s *AESGCMSealer) Seal(data []byte) ([]byte, error) {
	// If we don't have an AES key to encrypt the state, generate one
	if err := s.unsealEncryptionKey(); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if err := s.generateEncryptionKey(); err != nil {
			return nil, err
		}
	}

	// Create cipher object with the encryption key
	aesgcm, err := getCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}

	// encrypt
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	encData := aesgcm.Seal(nil, nonce, data, nil)

	// store to fs
	if err := ioutil.WriteFile(s.getFname("data"), append(nonce, encData...), 0600); err != nil {
		return nil, err
	}

	return s.encryptionKey, nil
}

func (s *AESGCMSealer) getFname(basename string) string {
	if basename == "data" {
		return filepath.Join(s.sealDir, sealedDataFname)
	} else if basename == "key" {
		return filepath.Join(s.sealDir, sealedKeyFname)
	} else {
		return ""
	}
}

func (s *AESGCMSealer) unsealEncryptionKey() error {
	if s.encryptionKey != nil {
		return nil
	}

	// Load sealed encryption key from fs
	sealedKeyData, err := ioutil.ReadFile(s.getFname("key"))
	if err != nil {
		return err
	}

	// Unseal encryption key
	aesgcm, err := getCipher(s.sealKey)
	if err != nil {
		return err
	}

	// Decrypt encryption key
	nonce, encKeyData := sealedKeyData[:aesgcm.NonceSize()], sealedKeyData[aesgcm.NonceSize():]

	keyData, err := aesgcm.Open(nil, nonce, encKeyData, nil)
	if err != nil {
		return err
	}

	// Restore encryption key
	s.encryptionKey = keyData

	return nil
}

// Generate random 128 Bit (16 Byte) key to encrypt the state
func (s *AESGCMSealer) generateEncryptionKey() error {
	encryptionKey := make([]byte, 16)

	_, err := rand.Read(encryptionKey)
	if err != nil {
		return err
	}

	// Create cipher object with the seal key
	aesgcm, err := getCipher(s.sealKey)
	if err != nil {
		return err
	}

	// Encrypt the encryption key with the seal key
	keyDataNonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(keyDataNonce); err != nil {
		return err
	}
	encKeyData := aesgcm.Seal(nil, keyDataNonce, encryptionKey, nil)

	// Write the sealed encryption key to disk
	if err = ioutil.WriteFile(s.getFname("key"), append(keyDataNonce, encKeyData...), 0600); err != nil {
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
