/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package pkcs11

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/ThalesGroup/crypto11"
)

// LoadX509KeyPair loads a [tls.Certificate] using the provided PKCS#11 configuration file.
// The returned cancel function must be called to release the PKCS#11 resources only after the certificate is no longer needed.
func LoadX509KeyPair(pkcs11ConfigPath string, keyID, keyLabel, certID, certLabel string) (crt tls.Certificate, cancel func() error, err error) {
	pkcs11, err := crypto11.ConfigureFromFile(pkcs11ConfigPath)
	if err != nil {
		return crt, nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, pkcs11.Close())
		}
	}()

	var keyIDBytes, keyLabelBytes, certIDBytes, certLabelBytes []byte
	if keyID != "" {
		keyIDBytes = []byte(keyID)
	}
	if keyLabel != "" {
		keyLabelBytes = []byte(keyLabel)
	}
	if certID != "" {
		certIDBytes = []byte(certID)
	}
	if certLabel != "" {
		certLabelBytes = []byte(certLabel)
	}

	privateKey, err := loadPrivateKey(pkcs11, keyIDBytes, keyLabelBytes)
	if err != nil {
		return crt, nil, err
	}
	cert, err := loadCertificate(pkcs11, certIDBytes, certLabelBytes)
	if err != nil {
		return crt, nil, err
	}

	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}, pkcs11.Close, nil
}

func loadPrivateKey(pkcs11 *crypto11.Context, id, label []byte) (crypto.Signer, error) {
	priv, err := pkcs11.FindKeyPair(id, label)
	if err != nil {
		return nil, err
	}
	if priv == nil {
		return nil, fmt.Errorf("no key pair found for id \"%s\" and label \"%s\"", id, label)
	}
	return priv, nil
}

func loadCertificate(pkcs11 *crypto11.Context, id, label []byte) (*x509.Certificate, error) {
	cert, err := pkcs11.FindCertificate(id, label, nil)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, fmt.Errorf("no certificate found for id \"%s\" and label \"%s\"", id, label)
	}
	return cert, nil
}