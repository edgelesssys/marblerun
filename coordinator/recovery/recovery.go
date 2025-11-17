/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package recovery

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// Recovery describes an interface which the core can use to choose a recoverer (e.g. only single-party recoverer, multi-party recoverer) depending on the version of MarbleRun.
type Recovery interface {
	GenerateEncryptionKey(recoveryKeys map[string]string) ([]byte, error)
	GenerateRecoveryData(recoveryKeys map[string]string) (map[string][]byte, []byte, error)
	RecoverKey(secret []byte) (int, []byte, error)
	SetRecoveryData(data []byte) error
}

func generateRandomKey() ([]byte, error) {
	generatedValue := make([]byte, 32)
	_, err := rand.Read(generatedValue)
	if err != nil {
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
