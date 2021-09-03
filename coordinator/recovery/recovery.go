// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package recovery

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// Recovery describes an interface which the core can use to choose a recoverer (e.g. only single-party recoverer, multi-party recoverer) depending on the version of MarbleRun.
type Recovery interface {
	GenerateEncryptionKey(recoveryKeys map[string]string) ([]byte, error)
	GenerateRecoveryData(recoveryKeys map[string]string) (map[string][]byte, []byte, error)
	RecoverKey(secret []byte) (int, []byte, error)
	GetRecoveryData() ([]byte, error)
	SetRecoveryData(data []byte) error
}

func parseRSAPublicKeyFromPEM(pemContent string) (*rsa.PublicKey, error) {
	// Retrieve RSA public key for potential key recovery
	block, _ := pem.Decode([]byte(pemContent))

	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid public key in manifest")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	recoveryk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("unsupported type of public key")
	}

	return recoveryk, nil
}

func generateRandomKey() ([]byte, error) {
	generatedValue := make([]byte, 16)
	_, err := rand.Read(generatedValue)
	if err != nil {
		return nil, err
	}

	return generatedValue, nil
}
