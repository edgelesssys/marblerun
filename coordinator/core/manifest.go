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
	"fmt"
	"text/template"

	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"go.uber.org/zap"
)

// Manifest defines the rules of a mesh.
type Manifest struct {
	// Packages contains the allowed enclaves and their properties.
	Packages map[string]quote.PackageProperties
	// Infrastructures contains the allowed infrastructure providers and their properties.
	Infrastructures map[string]quote.InfrastructureProperties
	// Marbles contains the allowed services with their corresponding enclave and configuration parameters.
	Marbles map[string]Marble
	// Admins contains user-generated TLS client certificates to be used for an administrator to perform manifest updates
	Admins map[string]string
	// Clients contains TLS certificates for authenticating clients that use the ClientAPI.
	Clients map[string][]byte
	// Secrets holds user-specified secrets, which should be generated and later on stored in a marble (if not shared) or in the core (if shared).
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
	Type     string
	Size     uint
	Shared   bool
	Cert     Certificate
	ValidFor uint
	Private  PrivateKey
	Public   PublicKey
}

// Certificate is an x509.Certificate
type Certificate x509.Certificate

// MarshalJSON implements the json.Marshaler interface.
func (c Certificate) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.Raw)
}

// UnmarshalJSON implements the json.Marshaler interface.
func (c *Certificate) UnmarshalJSON(data []byte) error {
	// This function is called either when unmarshalling the manifest or the sealed
	// state. Thus, data can be a JSON object ({...}) or a JSON string ("...").

	if data[0] != '"' {
		// Unmarshal the JSON object to an x509.Certificate.
		return json.Unmarshal(data, (*x509.Certificate)(c))
	}

	// Unmarshal and parse the raw certificate.
	var raw []byte
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return err
	}
	*c = Certificate(*cert)
	return nil
}

func encodeSecretDataToPem(data interface{}) (string, error) {
	var pemData []byte

	switch x := data.(type) {
	case Certificate:
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
	switch secret := data.(type) {
	case []byte:
		return string(secret), nil
	case PrivateKey:
		return string(secret), nil
	case PublicKey:
		return string(secret), nil
	case Secret:
		return string(secret.Public), nil
	case Certificate:
		return string(secret.Raw), nil
	default:
		return "", errors.New("invalid secret type")
	}
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
func (m Manifest) Check(ctx context.Context, zaplogger *zap.Logger) error {
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
		singlePackage, ok := m.Packages[marble.Package]
		if !ok {
			return errors.New("manifest does not contain marble package " + marble.Package)
		}
		// Check if package specifies either UniqueID, or values for all, SignerID, ProductID & Security version
		// Debug mode bypasses this requirement and throws a warning instead
		if singlePackage.UniqueID != "" && (singlePackage.SignerID != "" || singlePackage.ProductID != nil || singlePackage.SecurityVersion != nil) {
			if singlePackage.Debug {
				zaplogger.Warn("Manifest specifies UniqueID *and* SignerID/ProductID/SecurityVersion. This is not accepted in non-debug mode, please check your configuration.", zap.String("packageName", marble.Package))
			} else {
				return fmt.Errorf("manifest specfies both UniqueID *and* SignerID/ProductID/SecurityVersion in package %s", marble.Package)
			}
		} else if singlePackage.UniqueID == "" {
			if singlePackage.SignerID == "" {
				if err := warnOrFailForMissingValue(singlePackage.Debug, "SignerID", marble.Package, zaplogger); err != nil {
					return err
				}
			}
			if singlePackage.ProductID == nil {
				if err := warnOrFailForMissingValue(singlePackage.Debug, "ProductID", marble.Package, zaplogger); err != nil {
					return err
				}
			}
			if singlePackage.SecurityVersion == nil {
				if err := warnOrFailForMissingValue(singlePackage.Debug, "SecurityVersion", marble.Package, zaplogger); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// CheckUpdate checks if the manifest is consistent and only contains supported values.
func (m Manifest) CheckUpdate(ctx context.Context, originalPackages map[string]quote.PackageProperties, alreadyUpdatedPackages map[string]quote.PackageProperties) error {
	if len(m.Packages) <= 0 {
		return errors.New("no packages defined")
	}

	// Check if manifest update contains values which we normally should not update
	for packageName, singlePackage := range m.Packages {
		// Check if the original manifest does even contain the package we want to update
		if _, ok := originalPackages[packageName]; !ok {
			return errors.New("update manifest specifies a package which the original manifest does not contain")
		}

		// Check if singlePackages contains illegal values to update
		if singlePackage.Debug != false || singlePackage.UniqueID != "" || singlePackage.SignerID != "" || singlePackage.ProductID != nil {
			return errors.New("update manifest contains unupdatable values")
		}

		// Check if singlePackages does actually contain a SecurityVersion value
		if singlePackage.SecurityVersion == nil {
			return errors.New("update manifest does not specifiy a SecurityVersion to update")
		}

		// Check based on the original manifest
		if originalPackages[packageName].SecurityVersion != nil && *singlePackage.SecurityVersion < *originalPackages[packageName].SecurityVersion {
			return errors.New("update manifest tries to downgrade SecurityVersion of the original manifest")
		}

		// Checks if we already have an update manifest set, if it does contain the package and if it does, if it actually holds a value for SecurityVersion (which should always be the case, but let's go safe here)
		for alreadyUpdatedPackageName, alreadyUpdatedPackage := range alreadyUpdatedPackages {
			// Check if new update manifest contains all package entries which the current one does
			if _, ok := m.Packages[alreadyUpdatedPackageName]; !ok {
				return errors.New("update manifest misses package definitions of the currently set update manifest")
			}
			// If this is the case, check if the SecurityVersion is equal or higher than defined in the current one. No downgrades allowed
			if alreadyUpdatedPackage.SecurityVersion != nil && (*singlePackage.SecurityVersion < *alreadyUpdatedPackage.SecurityVersion) {
				return errors.New("update manifest tries to downgrade SecurityVersion of the currently set updated manifest")
			}
		}
	}

	return nil
}

func warnOrFailForMissingValue(debugMode bool, parameter string, packageName string, zaplogger *zap.Logger) error {
	if debugMode {
		zaplogger.Warn("Manifest misses value in package declaration. This is not accepted in non-debug mode, please check your configuration.", zap.String("parameter", parameter), zap.String("packageName", packageName))
		return nil
	}

	return fmt.Errorf("manifest misses value for %s in package %s", parameter, packageName)
}
