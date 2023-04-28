// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package seal

// NoEnclaveSealer is a sealed for a -noenclave instance and does perform encryption with a fixed key.
type NoEnclaveSealer struct {
	encryptionKey []byte
}

// NewNoEnclaveSealer creates and initializes a new NoEnclaveSealer object.
func NewNoEnclaveSealer() *NoEnclaveSealer {
	return &NoEnclaveSealer{}
}

// Unseal reads the plaintext state from disk.
func (s *NoEnclaveSealer) Unseal(sealedData []byte) ([]byte, []byte, error) {
	return unsealData(sealedData, s.encryptionKey)
}

// Seal writes the given data encrypted and the used key as plaintext to the disk.
func (s *NoEnclaveSealer) Seal(unencryptedData []byte, toBeEncrypted []byte) ([]byte, error) {
	return sealData(unencryptedData, toBeEncrypted, s.encryptionKey)
}

// SetEncryptionKey implements the Sealer interface.
func (s *NoEnclaveSealer) SetEncryptionKey(key []byte) ([]byte, error) {
	s.encryptionKey = key
	return nil, nil
}

// UnsealEncryptionKey implements the Sealer interface.
func (s *NoEnclaveSealer) UnsealEncryptionKey(key []byte) ([]byte, error) {
	return key, nil
}
