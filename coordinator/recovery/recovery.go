/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package recovery

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

const (
	// RecoveryKeySize is the size of recovery keys in bytes.
	RecoveryKeySize = 32
	// RecoveryKeySizeLegacy is the size of legacy recovery keys in bytes.
	RecoveryKeySizeLegacy = 16
)

// Recovery describes an interface which the core uses for recovery operations.
type Recovery interface {
	GenerateEncryptionKey(recoveryKeys map[string]string, recoveryThreshold uint) ([]byte, error)
	GenerateRecoveryData(recoveryKeys map[string]string) (map[string][]byte, []byte, error)
	RecoverKey(secret []byte) (int, []byte, error)
	SetRecoveryData(data []byte) error
	EphemeralPublicKey() (crypto.PublicKey, error)
	DecryptRecoverySecret(encryptedSecret []byte) ([]byte, error)
}

func generateRandomKey() ([]byte, error) {
	generatedValue := make([]byte, RecoveryKeySize)
	if _, err := rand.Read(generatedValue); err != nil {
		return nil, err
	}

	return generatedValue, nil
}

// Hash computes the SHA256 hash of the input and returns it as a hex-encoded string.
func Hash(input []byte) string {
	hashSum := sha256.Sum256(input)
	hashSumString := hex.EncodeToString(hashSum[:])

	return hashSumString
}
