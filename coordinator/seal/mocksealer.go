// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package seal

// MockSealer is a mockup sealer.
type MockSealer struct {
	data            []byte
	unencryptedData []byte
	// mock unseal error
	UnsealError error
}

// Unseal implements the Sealer interface.
func (s *MockSealer) Unseal(_ []byte) ([]byte, []byte, error) {
	return s.unencryptedData, s.data, s.UnsealError
}

// Seal implements the Sealer interface.
func (s *MockSealer) Seal(unencryptedData []byte, toBeEncrypted []byte) ([]byte, error) {
	s.unencryptedData = unencryptedData
	s.data = toBeEncrypted
	return toBeEncrypted, nil
}

// SealEncryptionKey implements the Sealer interface.
// Since the MockSealer does not support sealing with an enclave key, it returns the key as is.
func (s *MockSealer) SealEncryptionKey(key []byte) ([]byte, error) {
	return key, nil
}

// SetEncryptionKey implements the Sealer interface.
func (s *MockSealer) SetEncryptionKey(_ []byte) {}

// UnsealEncryptionKey implements the Sealer interface.
func (s *MockSealer) UnsealEncryptionKey(key []byte) ([]byte, error) {
	return key, nil
}
