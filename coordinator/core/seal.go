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

const defaultSealedDataFname string = "sealed_data"
const defaultSealedKeyFname string = "sealed_key"

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
	sealedData, err := ioutil.ReadFile(s.getFname())
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	if s.encryptionKey == nil {
		if err = s.unsealEncryptionKey(); err != nil {
			panic(err)
		}
	}

	// Use encryption key to decrypt state
	aesgcm_encryptionkey, err := s.getCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}

	// decrypt
	nonce, encData := sealedData[:aesgcm_encryptionkey.NonceSize()], sealedData[aesgcm_encryptionkey.NonceSize():]
	data, err := aesgcm_encryptionkey.Open(nil, nonce, encData, nil)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// Seal encrypts and stores information to the fs
func (s *AESGCMSealer) Seal(data []byte) ([]byte, error) {
	// If we don't have an AES key to encrypt the state, generate one
	if s.unsealEncryptionKey() != nil && s.encryptionKey == nil {
		s.generateEncryptionKey()
	}

	// Create cipher object with the encryption key
	aesgcm_encryptionkey, err := s.getCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}

	// encrypt
	nonce := make([]byte, aesgcm_encryptionkey.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	encData := aesgcm_encryptionkey.Seal(nil, nonce, data, nil)

	// store to fs
	ioutil.WriteFile(s.getFname(), append(nonce, encData...), 0600)
	if err != nil {
		return nil, err
	}

	return s.encryptionKey, nil
}

func (s *AESGCMSealer) getFname() string {
	return filepath.Join(s.sealDir, defaultSealedDataFname)
}

func (s *AESGCMSealer) getSealedKeyFname() string {
	return filepath.Join(s.sealDir, defaultSealedKeyFname)
}

func (s *AESGCMSealer) getCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *AESGCMSealer) unsealEncryptionKey() error {
	// Load sealed encryption key from fs
	sealedKeyData, err := ioutil.ReadFile(s.getSealedKeyFname())
	if err != nil {
		return err
	}

	// Unseal encryption key
	aesgcm_sealkey, err := s.getCipher(s.sealKey)
	if err != nil {
		return err
	}

	// Decrypt encryption key
	nonce, encKeyData := sealedKeyData[:aesgcm_sealkey.NonceSize()], sealedKeyData[aesgcm_sealkey.NonceSize():]

	keyData, err := aesgcm_sealkey.Open(nil, nonce, encKeyData, nil)
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
		panic(err)
	}

	// Create cipher object with the seal key
	aesgcm_sealkey, err := s.getCipher(s.sealKey)
	if err != nil {
		return err
	}

	// Encrypt the encryption key with the seal key
	keyDataNonce := make([]byte, aesgcm_sealkey.NonceSize())
	if _, err := rand.Read(keyDataNonce); err != nil {
		return err
	}
	encKeyData := aesgcm_sealkey.Seal(nil, keyDataNonce, encryptionKey, nil)

	// Write the sealed encryption key to disk
	if err = ioutil.WriteFile(s.getSealedKeyFname(), append(keyDataNonce, encKeyData...), 0600); err != nil {
		return err
	}

	s.encryptionKey = encryptionKey

	return err
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
	return nil, nil
}
