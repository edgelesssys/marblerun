package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io/ioutil"
	"os"
	"path/filepath"
)

const defaultSealFname string = "sealed_data"

// Sealer is an interface for the Core object to seal information to the filesystem for persistence
type Sealer interface {
	Seal(data []byte) error
	Unseal() ([]byte, error)
}

// AESGCMSealer implements the Sealer interface using AES-GCM for confidentiallity and authentication
type AESGCMSealer struct {
	sealDir string
	sealKey []byte
}

// NewAESGCMSealer creates and initializes a new AESGCMSealer object
func NewAESGCMSealer(sealDir string, sealKey []byte) *AESGCMSealer {
	return &AESGCMSealer{sealDir: sealDir, sealKey: sealKey}
}

// Unseal reads and decrypts stored information from the fs
func (s *AESGCMSealer) Unseal() ([]byte, error) {
	aesgcm, err := s.getCipher()
	if err != nil {
		return nil, err
	}

	// load from fs
	sealedData, err := ioutil.ReadFile(s.getFname())
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
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
func (s *AESGCMSealer) Seal(data []byte) error {
	aesgcm, err := s.getCipher()
	if err != nil {
		return err
	}

	// encrypt
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	encData := aesgcm.Seal(nil, nonce, data, nil)

	// store to fs
	return ioutil.WriteFile(s.getFname(), append(nonce, encData...), 0600)
}

func (s *AESGCMSealer) getFname() string {
	return filepath.Join(s.sealDir, defaultSealFname)
}

func (s *AESGCMSealer) getCipher() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.sealKey)
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
func (s *MockSealer) Seal(data []byte) error {
	s.data = data
	return nil
}
