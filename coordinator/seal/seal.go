// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package seal

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/edgelesssys/ego/ecrypto"
)

// SealedDataFname contains the file name in which the state is sealed on disk in seal_dir.
const SealedDataFname string = "sealed_data"

// SealedKeyFname contains the file name in which the key is sealed with the seal key on disk in seal_dir.
const SealedKeyFname string = "sealed_key"

// ErrEncryptionKey occurs if unsealing the encryption key failed.
var ErrEncryptionKey = errors.New("cannot unseal encryption key")

// Sealer is an interface for the Core object to seal information to the filesystem for persistence.
type Sealer interface {
	Seal(unencryptedData []byte, toBeEncrypted []byte) error
	Unseal() (unencryptedData []byte, decryptedData []byte, err error)
	SetEncryptionKey(key []byte) error
}

// AESGCMSealer implements the Sealer interface using AES-GCM for confidentiallity and authentication.
type AESGCMSealer struct {
	sealDir       string
	encryptionKey []byte
}

// NewAESGCMSealer creates and initializes a new AESGCMSealer object.
func NewAESGCMSealer(sealDir string) *AESGCMSealer {
	return &AESGCMSealer{sealDir: sealDir}
}

// Unseal reads and decrypts stored information from the fs.
func (s *AESGCMSealer) Unseal() ([]byte, []byte, error) {
	// load from fs
	sealedData, err := ioutil.ReadFile(s.getFname(SealedDataFname))

	if os.IsNotExist(err) {
		// No sealed data found, back up any existing seal keys
		s.backupEncryptionKey()
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, err
	}

	if len(sealedData) <= 4 {
		return nil, nil, errors.New("sealed state is missing data")
	}

	// Retrieve recovery secret hash map
	encodedUnencryptDataLength := binary.LittleEndian.Uint32(sealedData[:4])

	// Check if we do not go out of bounds
	if 4+encodedUnencryptDataLength > uint32(len(sealedData)) {
		return nil, nil, errors.New("sealed state is corrupted, embedded length does not fit the data")
	}

	var unencryptedData []byte
	if encodedUnencryptDataLength != 0 {
		unencryptedData = sealedData[4 : 4+encodedUnencryptDataLength]
	}
	ciphertext := sealedData[4+encodedUnencryptDataLength:]

	// Decrypt generated encryption key with seal key, if needed
	if err = s.unsealEncryptionKey(); err != nil {
		return unencryptedData, nil, ErrEncryptionKey
	}

	// Decrypt data with the unsealed encryption key and return it
	decryptedData, err := ecrypto.Decrypt(ciphertext, s.encryptionKey, nil)
	if err != nil {
		return unencryptedData, nil, err
	}

	return unencryptedData, decryptedData, nil
}

// Seal encrypts and stores information to the fs.
func (s *AESGCMSealer) Seal(unencryptedData []byte, toBeEncrypted []byte) error {
	// If we don't have an AES key to encrypt the state, generate one
	if err := s.unsealEncryptionKey(); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if err := s.generateNewEncryptionKey(); err != nil {
			return err
		}
	}

	// Encrypt data to seal with generated encryption key
	encryptedData, err := ecrypto.Encrypt(toBeEncrypted, s.encryptionKey, nil)
	if err != nil {
		return err
	}

	unencryptDataLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(unencryptDataLength, uint32(len(unencryptedData)))
	unencryptedData = append(unencryptDataLength, unencryptedData...)

	// Append unencrypted data with encrypted data
	encryptedData = append(unencryptedData, encryptedData...)

	// store to fs
	if err := ioutil.WriteFile(s.getFname(SealedDataFname), encryptedData, 0o600); err != nil {
		return err
	}

	return nil
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
	encryptionKey, err := ecrypto.Unseal(sealedKeyData, nil)
	if err != nil {
		return err
	}

	// Restore encryption key
	s.encryptionKey = encryptionKey

	return nil
}

// generateNewEncryptionKey generates a random 128 Bit (16 Byte) key to encrypt the state.
func (s *AESGCMSealer) generateNewEncryptionKey() error {
	encryptionKey := make([]byte, 16)

	_, err := rand.Read(encryptionKey)
	if err != nil {
		return err
	}

	return s.SetEncryptionKey(encryptionKey)
}

// SetEncryptionKey sets or restores an encryption key.
func (s *AESGCMSealer) SetEncryptionKey(encryptionKey []byte) error {
	// If there already is an existing key file stored on disk, save it
	s.backupEncryptionKey()

	// Encrypt encryption key with seal key
	encryptedKeyData, err := ecrypto.SealWithProductKey(encryptionKey, nil)
	if err != nil {
		return err
	}

	// Write the sealed encryption key to disk
	if err = ioutil.WriteFile(s.getFname(SealedKeyFname), encryptedKeyData, 0o600); err != nil {
		return err
	}

	s.encryptionKey = encryptionKey

	return nil
}

// backupEncryptionKey creates a backup of an existing seal key.
func (s *AESGCMSealer) backupEncryptionKey() {
	if sealedKeyData, err := ioutil.ReadFile(s.getFname(SealedKeyFname)); err == nil {
		t := time.Now()
		newFileName := s.getFname(SealedKeyFname) + "_" + t.Format("20060102150405") + ".bak"
		ioutil.WriteFile(newFileName, sealedKeyData, 0o600)
	}
}

// MockSealer is a mockup sealer.
type MockSealer struct {
	data            []byte
	unencryptedData []byte
	// mock unseal error
	UnsealError error
}

// Unseal implements the Sealer interface.
func (s *MockSealer) Unseal() ([]byte, []byte, error) {
	return s.unencryptedData, s.data, s.UnsealError
}

// Seal implements the Sealer interface.
func (s *MockSealer) Seal(unencryptedData []byte, toBeEncrypted []byte) error {
	s.unencryptedData = unencryptedData
	s.data = toBeEncrypted
	return nil
}

// SetEncryptionKey implements the Sealer interface.
func (s *MockSealer) SetEncryptionKey(key []byte) error {
	return nil
}

// NoEnclaveSealer is a sealed for a -noenclave instance and does perform encryption with a fixed key.
type NoEnclaveSealer struct {
	sealDir       string
	encryptionKey []byte
}

// NewNoEnclaveSealer creates and initializes a new NoEnclaveSealer object.
func NewNoEnclaveSealer(sealDir string) *NoEnclaveSealer {
	return &NoEnclaveSealer{sealDir: sealDir}
}

// Seal writes the given data encrypted and the used key as plaintext to the disk.
func (s *NoEnclaveSealer) Seal(unencryptedData []byte, toBeEncrypted []byte) error {
	// generate aes key if we have non
	if err := s.loadEncryptionKey(); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if err := s.generateNewEncryptionKey(); err != nil {
			return err
		}
	}

	// Encrypt data
	sealedData, err := ecrypto.Encrypt(toBeEncrypted, s.encryptionKey, nil)
	if err != nil {
		return err
	}

	unencryptDataLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(unencryptDataLength, uint32(len(unencryptedData)))
	unencryptedData = append(unencryptDataLength, unencryptedData...)

	// Append unencrypted data with encrypted data
	sealedData = append(unencryptedData, sealedData...)

	// Write encrypted data to disk
	if err := ioutil.WriteFile(s.getFname(SealedDataFname), sealedData, 0o600); err != nil {
		return err
	}

	// Write key in plaintext to disk
	if err := ioutil.WriteFile(s.getFname(SealedKeyFname), s.encryptionKey, 0o600); err != nil {
		return err
	}
	return nil
}

// Unseal reads the plaintext state from disk.
func (s *NoEnclaveSealer) Unseal() ([]byte, []byte, error) {
	// Read sealed data from disk
	sealedData, err := ioutil.ReadFile(s.getFname(SealedDataFname))
	if os.IsNotExist(err) {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, err
	}

	// Read key in plaintext from disk
	keyData, err := ioutil.ReadFile(s.getFname(SealedKeyFname))
	if err != nil {
		return nil, nil, err
	}

	// Retrieve recovery secret hash map
	encodedUnencryptDataLength := binary.LittleEndian.Uint32(sealedData[:4])

	// Check if we do not go out of bounds
	if 4+int(encodedUnencryptDataLength) > len(sealedData) {
		return nil, nil, errors.New("sealed state is corrupted, embedded length does not fit the data")
	}

	var unencryptedData []byte
	if encodedUnencryptDataLength != 0 {
		unencryptedData = sealedData[4 : 4+encodedUnencryptDataLength]
	}
	ciphertext := sealedData[4+encodedUnencryptDataLength:]

	// Decrypt data with key from disk
	decryptedData, err := ecrypto.Decrypt(ciphertext, keyData, nil)
	if err != nil {
		return unencryptedData, nil, ErrEncryptionKey
	}

	return unencryptedData, decryptedData, nil
}

// SetEncryptionKey implements the Sealer interface.
func (s *NoEnclaveSealer) SetEncryptionKey(key []byte) error {
	s.encryptionKey = key
	return ioutil.WriteFile(s.getFname(SealedKeyFname), s.encryptionKey, 0o600)
}

func (s *NoEnclaveSealer) getFname(basename string) string {
	return filepath.Join(s.sealDir, basename)
}

func (s *NoEnclaveSealer) loadEncryptionKey() error {
	if s.encryptionKey != nil {
		return nil
	}

	encrytpionKey, err := ioutil.ReadFile(s.getFname(SealedKeyFname))
	if err != nil {
		return err
	}

	s.encryptionKey = encrytpionKey
	return nil
}

// generateNewEncryptionKey generates a random 128 Bit (16 Byte) key to encrypt the state.
func (s *NoEnclaveSealer) generateNewEncryptionKey() error {
	encryptionKey := make([]byte, 16)

	_, err := rand.Read(encryptionKey)
	if err != nil {
		return err
	}

	return s.SetEncryptionKey(encryptionKey)
}
