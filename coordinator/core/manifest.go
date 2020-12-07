// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"text/template"

	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/rpc"
)

// Manifest defines the rules of a mesh.
type Manifest struct {
	// Packages contains the allowed enclaves and their properties.
	Packages map[string]quote.PackageProperties
	// Infrastructures contains the allowed infrastructure providers and their properties.
	Infrastructures map[string]quote.InfrastructureProperties
	// Marbles contains the allowed services with their corresponding enclave and configuration parameters.
	Marbles map[string]Marble
	// Clients contains TLS certificates for authenticating clients that use the ClientAPI.
	Clients map[string][]byte
	// Secrets holds user-specified secrets, which should be generated and later on stored in the core.
	Secrets map[string]Secret
	// Recovery holds a RSA public key to encrypt the state encryption key, which gets returned over the Client API when setting a manifest.
	RecoveryKey string
}

// Marble describes a service in the mesh that should be handled and verified by the Coordinator
type Marble struct {
	// Package references one of the allowed enclaves in the manifest.
	Package string
	// MaxActivations allows to limit the number of marbles of a kind.
	MaxActivations uint
	// Parameters contains lists for files, environment variables and commandline arguments that should be passed to the application.
	// Placeholder variables are supported for specific assets of the marble's activation process.
	Parameters *rpc.Parameters
}

// Secret describes a structure for storing certificates and keys, which can be used in combination with the go templating engine.

// PrivateKey is a wrapper for a binary private key, which we need for type differentiation in the PEM encoding function
type PrivateKey []byte

// PublicKey is a wrapper for a binary public key, which we need for type differentiation in the PEM encoding function
type PublicKey []byte

// Secret defines a structure for storing certificates & encryption keys
type Secret struct {
	Type        string
	Size        uint
	Cert        x509.Certificate `json:",omitempty"`
	CertEncoded string
	ValidFor    uint
	Private     PrivateKey
	Public      PublicKey
}

// MarshalJSON defines a custom marshaller which does not export a x509.Certificate object, otherwise we will be running into bugs due to JSON marshalled BitInts
func (s Secret) MarshalJSON() ([]byte, error) {
	type SecretWithoutCert struct {
		Type        string
		Size        uint
		CertEncoded string
		ValidFor    uint
		Private     PrivateKey
		Public      PublicKey
	}

	// Convert certificate object to PEM when marshalling to JSON (e.g. sealing the state)
	if s.Cert.Raw != nil {
		pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Cert.Raw})
		s.CertEncoded = string(pemData)
	}

	secretWithoutCert := SecretWithoutCert{
		Type:        s.Type,
		Size:        s.Size,
		CertEncoded: s.CertEncoded,
		ValidFor:    s.ValidFor,
		Private:     s.Private,
		Public:      s.Public,
	}

	return json.Marshal(secretWithoutCert)
}

func encodeSecretDataToPem(data interface{}) (string, error) {
	var pemData []byte

	switch x := data.(type) {
	case x509.Certificate:
		pemData = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x.Raw})
	case PublicKey:
		pemData = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x})
	case PrivateKey:
		pemData = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x})
	default:
		return "", errors.New("invalid secret type")
	}

	return string(pemData), nil
}

func encodeSecretDataToHex(data interface{}) (string, error) {
	raw, err := encodeSecretDataToRaw(data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString([]byte(raw)), nil
}
func encodeSecretDataToRaw(data interface{}) (string, error) {
	if bytes, ok := data.([]byte); ok {
		return string(bytes), nil
	}
	if secret, ok := data.(Secret); ok {
		return string(secret.Public), nil
	}
	if cert, ok := data.(x509.Certificate); ok {
		return string(cert.Raw), nil
	}
	return "", errors.New("invalid secret type")
}

func encodeSecretDataToBase64(data interface{}) (string, error) {
	raw, err := encodeSecretDataToRaw(data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(raw)), nil
}

var manifestTemplateFuncMap = template.FuncMap{
	"pem":    encodeSecretDataToPem,
	"hex":    encodeSecretDataToHex,
	"raw":    encodeSecretDataToRaw,
	"base64": encodeSecretDataToBase64,
}

// Check checks if the manifest is consistent.
func (m Manifest) Check(ctx context.Context) error {
	if len(m.Packages) <= 0 {
		return errors.New("no allowed packages defined")
	}
	if len(m.Marbles) <= 0 {
		return errors.New("no allowed marbles defined")
	}
	// if len(m.Infrastructures) <= 0 {
	// 	return errors.New("no allowed infrastructures defined")
	// }
	for _, marble := range m.Marbles {
		if _, ok := m.Packages[marble.Package]; !ok {
			return errors.New("manifest does not contain marble package " + marble.Package)
		}
	}
	return nil
}
