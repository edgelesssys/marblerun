package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

// sealedState represents the state information, required for persistence, that gets sealed to the filesystem
type sealedState struct {
	Privk          ed25519.PrivateKey
	RawManifest    []byte
	RawCert        []byte
	State          state
	ActivationsMap map[string]uint
}

// Sealer is an interface for the Core object to seal information to the filesystem for persistence
type Sealer interface {
	Seal(data []byte) error
	Unseal() ([]byte, error)
}

// AESGCMSealer implements the Sealer interface using AES-GCM for confidentiallity and authentication
type AESGCMSealer struct {
	SealDir string
	SealKey []byte
}

// Unseal reads and decrypts stored information from the fs
func (s AESGCMSealer) Unseal() ([]byte, error) {
	// load from fs
	dataFname := filepath.Join(s.SealDir, "sealed_data")
	sealedData, err := ioutil.ReadFile(dataFname)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	// decrypt
	block, err := aes.NewCipher(s.SealKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, encData := sealedData[:aesgcm.NonceSize()], sealedData[aesgcm.NonceSize():]

	data, err := aesgcm.Open(nil, nonce, encData, nil)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// Seal encrypts and stores information to the fs
func (s AESGCMSealer) Seal(data []byte) error {
	dataFname := filepath.Join(s.SealDir, "sealed_data")

	// encrypt
	block, err := aes.NewCipher(s.SealKey)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	encData := aesgcm.Seal(nil, nonce, data, nil)

	// store to fs
	if err := ioutil.WriteFile(dataFname, append(nonce, encData...), 0600); err != nil {
		return err
	}
	return nil
}
