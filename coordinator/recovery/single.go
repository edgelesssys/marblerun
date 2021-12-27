// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package recovery

import (
	"errors"

	"github.com/edgelesssys/marblerun/util"
)

// SinglePartyRecovery is a recoverer with support for single-party recovery only.
type SinglePartyRecovery struct {
	encryptionKey []byte
}

// NewSinglePartyRecovery generates a single-party recoverer which the core can use to call recovery functions.
func NewSinglePartyRecovery() *SinglePartyRecovery {
	return &SinglePartyRecovery{}
}

// GenerateEncryptionKey generates an encryption key according to the implicitly defined recovery mode.
func (r *SinglePartyRecovery) GenerateEncryptionKey(recoveryKeys map[string]string) ([]byte, error) {
	// Generate a single random key for single-party recovery, or generate multiple keys and XOR them together for multi-party recovery
	if len(recoveryKeys) > 1 {
		return nil, errors.New("multi-party recovery is not supported in this version of MarbleRun")
	}

	var err error
	r.encryptionKey, err = generateRandomKey()

	if err != nil {
		return nil, err
	}
	return r.encryptionKey, nil
}

// GenerateRecoveryData generates the recovery data which is returned to the user.
func (r *SinglePartyRecovery) GenerateRecoveryData(recoveryKeys map[string]string) (map[string][]byte, []byte, error) {
	// For single party recovery, just create a new map here and return one single key
	secretMap := make(map[string][]byte, 1)
	for index, value := range recoveryKeys {
		// Parse RSA Public Key
		recoveryk, err := parseRSAPublicKeyFromPEM(value)
		if err != nil {
			return nil, nil, err
		}

		// Encrypt encryption key with user-specified RSA public key
		secretMap[index], err = util.EncryptOAEP(recoveryk, r.encryptionKey)
		if err != nil {
			return nil, nil, err
		}
	}

	// Return freshly generated map for single-party recovery
	return secretMap, nil, nil
}

// RecoverKey is called by the client api and directly returns the recovery key (this is different for multi-party recovery in other versions of MarbleRun).
func (r *SinglePartyRecovery) RecoverKey(secret []byte) (int, []byte, error) {
	return 0, secret, nil
}

// GetRecoveryData returns the current recovery hash map. Given that we do not need to store any additional data in the state for Single Party Recovery, it does nothing here.
func (r *SinglePartyRecovery) GetRecoveryData() ([]byte, error) {
	return nil, nil
}

// SetRecoveryData sets the recovery hash map retrieved from the sealer on (failed) decryption. Given that we do not need to store any additional data in the state for Single Party Recovery, it does nothing here.
func (r *SinglePartyRecovery) SetRecoveryData(data []byte) error {
	return nil
}
