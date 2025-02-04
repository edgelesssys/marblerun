/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package seal

// MockSealer is a mockup sealer.
type MockSealer struct {
	data            []byte
	unencryptedData []byte
	key             []byte
	// mock unseal error
	UnsealError error
}

// Unseal implements the Sealer interface.
func (s *MockSealer) Unseal(_ []byte) ([]byte, []byte, error) {
	return s.unencryptedData, s.data, s.UnsealError
}

// UnsealWithKey implements the Sealer interface.
func (s *MockSealer) UnsealWithKey(_, _ []byte) ([]byte, []byte, error) {
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
func (s *MockSealer) SealEncryptionKey(_ []byte, mode Mode) ([]byte, error) {
	if mode == ModeProductKey || mode == ModeUniqueKey {
		return s.key, nil
	}
	panic("invariant not met: unexpected mode")
}

// SetEncryptionKey implements the Sealer interface.
func (s *MockSealer) SetEncryptionKey(key []byte) {
	s.key = key
}

// UnsealEncryptionKey implements the Sealer interface.
func (s *MockSealer) UnsealEncryptionKey(key, _ []byte) ([]byte, error) {
	return key, nil
}
