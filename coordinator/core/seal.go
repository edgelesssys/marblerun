// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"crypto/rand"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/edgelesssys/ertgolib/ertcrypto"
)

// SealedDataFname contains the file name in which the state is sealed on disk in seal_dir
const SealedDataFname string = "sealed_data"

// SealedKeyFname contains the file name in which the key is sealed with the seal key on disk in seal_dir
const SealedKeyFname string = "sealed_key"

// ErrEncryptionKey occurs if unsealing the encryption key failed.
var ErrEncryptionKey = errors.New("cannot unseal encryption key")

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
	encryptionKey []byte
}

// NewAESGCMSealer creates and initializes a new AESGCMSealer object
func NewAESGCMSealer(sealDir string) *AESGCMSealer {
	return &AESGCMSealer{sealDir: sealDir}
}

// Unseal reads and decrypts stored information from the fs
func (s *AESGCMSealer) Unseal() ([]byte, error) {
	// load from fs
	sealedData, err := ioutil.ReadFile(s.getFname(SealedDataFname))

	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	// Decrypt generated encryption key with seal key, if needed
	if err = s.unsealEncryptionKey(); err != nil {
		return nil, ErrEncryptionKey
	}

	// Decrypt data with the unsealed encryption key and return it
	return ertcrypto.Decrypt(sealedData, s.encryptionKey)
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
	encryptedData, err := ertcrypto.Encrypt(data, s.encryptionKey)
	if err != nil {
		return nil, err
	}

	// store to fs
	if err := ioutil.WriteFile(s.getFname(SealedDataFname), encryptedData, 0600); err != nil {
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
	sealedKeyData, err := ioutil.ReadFile(s.getFname(SealedKeyFname))
	if err != nil {
		return err
	}

	// Decrypt stored encryption key with seal key
	encryptionKey, err := ertcrypto.Unseal(sealedKeyData)
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
	if sealedKeyData, err := ioutil.ReadFile(s.getFname(SealedKeyFname)); err == nil {
		t := time.Now()
		newFileName := s.getFname(SealedKeyFname) + "_" + t.Format("20060102150405") + ".bak"
		ioutil.WriteFile(newFileName, sealedKeyData, 0600)
	}

	// Encrypt encryption key with seal key
	encryptedKeyData, err := ertcrypto.SealWithProductKey(encryptionKey)
	if err != nil {
		return err
	}

	// Write the sealed encryption key to disk
	if err = ioutil.WriteFile(s.getFname(SealedKeyFname), encryptedKeyData, 0600); err != nil {
		return err
	}

	s.encryptionKey = encryptionKey

	return nil
}

// MockSealer is a mockup sealer
type MockSealer struct {
	data        []byte
	unsealError error
}

// Unseal implements the Sealer interface
func (s *MockSealer) Unseal() ([]byte, error) {
	return s.data, s.unsealError
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

// NoEnclaveSealer is a sealed for a -noenclave instance and does perform encryption with a fixed key
type NoEnclaveSealer struct {
	sealDir       string
	encryptionKey []byte
}

// NewNoEnclaveSealer creates and initializes a new NoEnclaveSealer object
func NewNoEnclaveSealer(sealDir string) *NoEnclaveSealer {
	return &NoEnclaveSealer{sealDir: sealDir}
}

// Seal writes the given data encrypted and the used key as plaintext to the disk
func (s *NoEnclaveSealer) Seal(data []byte) ([]byte, error) {
	// Encrypt data
	sealedData, err := ertcrypto.Encrypt(data, s.encryptionKey)
	if err != nil {
		return nil, err
	}

	// Write encrypted data to disk
	if err := ioutil.WriteFile(s.getFname(SealedDataFname), sealedData, 0600); err != nil {
		return nil, err
	}

	// Write key in plaintext to disk
	if err := ioutil.WriteFile(s.getFname(SealedKeyFname), s.encryptionKey, 0600); err != nil {
		return nil, err
	}
	return s.encryptionKey, nil
}

// Unseal reads the plaintext state from disk
func (s *NoEnclaveSealer) Unseal() ([]byte, error) {
	// Read sealed data from disk
	sealedData, err := ioutil.ReadFile(s.getFname(SealedDataFname))
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	// Read key in plaintext from disk
	keyData, err := ioutil.ReadFile(s.getFname(SealedKeyFname))
	if err != nil {
		return nil, err
	}

	// Decrypt data with key from disk
	data, err := ertcrypto.Decrypt(sealedData, keyData)
	if err != nil {
		return nil, ErrEncryptionKey
	}

	return data, nil
}

// SetEncryptionKey implements the Sealer interface
func (s *NoEnclaveSealer) SetEncryptionKey(key []byte) error {
	s.encryptionKey = key
	return ioutil.WriteFile(s.getFname(SealedKeyFname), s.encryptionKey, 0600)
}

// GenerateNewEncryptionKey implements the Sealer interface
func (s *NoEnclaveSealer) GenerateNewEncryptionKey() error {
	s.encryptionKey = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	return nil
}

func (s *NoEnclaveSealer) getFname(basename string) string {
	return filepath.Join(s.sealDir, basename)
}
