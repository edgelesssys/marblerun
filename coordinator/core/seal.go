package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
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
	SealDir string
	SealKey []byte
}

// NewAESGCMSealer creates and initializes a new AESGCMSealer object
func NewAESGCMSealer(sealDir string, sealKey []byte) *AESGCMSealer {
	return &AESGCMSealer{SealDir: sealDir, SealKey: sealKey}
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
func (s *AESGCMSealer) Seal(data []byte) error {
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
	return ioutil.WriteFile(s.getFname(), append(nonce, encData...), 0600)
}

func (s *AESGCMSealer) getFname() string {
	return filepath.Join(s.SealDir, defaultSealFname)
}

// MockSealer is a mockup sealer
type MockSealer struct {
	data []byte
}

// NewMockSealer creates and initializes a new MockSealer object
func NewMockSealer() *MockSealer {
	return &MockSealer{}
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
