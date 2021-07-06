// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package manifest

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"text/template"

	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"github.com/edgelesssys/marblerun/coordinator/user"
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
	// Users contains user definitions, including certificates used for authentication and permissions.
	Users map[string]User
	// Clients contains TLS certificates for authenticating clients that use the ClientAPI.
	Clients map[string][]byte
	// Secrets holds user-specified secrets, which should be generated and later on stored in a marble (if not shared) or in the core (if shared).
	Secrets map[string]Secret
	// RecoveryKeys holds one or multiple RSA public keys to encrypt multiple secrets, which can be used to decrypt the sealed state again in case the encryption key on disk was corrupted somehow.
	RecoveryKeys map[string]string
	// Roles contains role definitions to manage permissions across the Marblerun mesh
	Roles map[string]Role
	// TLS contains tags which can be assiged to Marbles to specify which connections should be elevated to TLS
	TLS map[string]TLStag
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
	// TLS holds a list of tags which are specified in the manifest
	TLS []string
}

// TLStag describes which entries should be used to determine the ttls connections of a marble
type TLStag struct {
	// Outgoing holds a list of all outgoing addresses that should be elevated to TLS
	Outgoing []TLSTagEntry
	// Incoming holds a list of all incoming addresses that should be elevated to TLS
	Incoming []TLSTagEntry
}

// TLSTagEntry describes one connection which should be elevated to ttls
type TLSTagEntry struct {
	Port              string
	Addr              string
	Cert              string
	DisableClientAuth bool
}

// User describes the attributes of a Marblerun user
type User struct {
	// Certificate is the TLS certificate used by the user for authentication
	Certificate string
	// Roles is a list of roles granting permissions to the user
	Roles []string
}

// Role describes a set of actions permitted for a specific set of resources
type Role struct {
	// ResourceType is the type of the affected resources
	ResourceType string
	// ResourceNames is a list of names of type ResourceType
	ResourceNames []string
	// Actions are the allowed actions for the defined resources
	Actions []string
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
		for _, tag := range marble.TLS {
			if _, ok := m.TLS[tag]; !ok {
				return fmt.Errorf("manifest misses TLS entry for %s", tag)
			}
		}
	}
	for key, TLStag := range m.TLS {
		for _, entry := range TLStag.Incoming {
			if entry.Port == "" {
				return fmt.Errorf("manifest misses Port in TLS.Incoming.%s", key)
			}
			if entry.Cert != "" {
				if _, ok := m.Secrets[entry.Cert]; !ok {
					return fmt.Errorf("TLS.Incoming.%s references undefined secret %s", key, entry.Cert)
				}
				if !entry.DisableClientAuth {
					return fmt.Errorf("TLS.Incoming.%s defines Cert but does not disable client authentication", key)
				}
			} else {
				if entry.DisableClientAuth {
					return fmt.Errorf("TLS.Incoming.%s disables client authentication", key)
				}
			}
		}
		for _, entry := range TLStag.Outgoing {
			if entry.Addr == "" {
				return fmt.Errorf("manifest misses Addr in TLS.Outgoing.%s", key)
			}
			if entry.Port == "" {
				return fmt.Errorf("manifest misses Port in TLS.Outgoing.%s", key)
			}
		}
	}

	for userName, user := range m.Users {
		if len(user.Certificate) <= 0 {
			return fmt.Errorf("manifest does not contain a certificate for user %s", userName)
		}
		for _, role := range user.Roles {
			if _, ok := m.Roles[role]; !ok {
				return fmt.Errorf("manifest specifies role %s for user %s, but role does not exist", role, userName)
			}
		}
	}

	for roleName, role := range m.Roles {
		switch role.ResourceType {
		case "Packages":
			for _, resource := range role.ResourceNames {
				if _, ok := m.Packages[resource]; !ok {
					return fmt.Errorf("role %s: resource %s of type Packages is not defined in manifest", roleName, resource)
				}
			}
			for _, action := range role.Actions {
				if !(strings.ToLower(action) == user.PermissionUpdatePackage) {
					return fmt.Errorf("unkown action: %s for type Packages in role: %s", action, roleName)
				}
			}
		case "Secrets":
			var writeRole bool
			var readRole bool
			for _, action := range role.Actions {
				if !(strings.ToLower(action) == user.PermissionWriteSecret || strings.ToLower(action) == user.PermissionReadSecret) {
					return fmt.Errorf("unkown action: %s for type Secrets in role: %s", action, roleName)
				}
				if strings.ToLower(action) == user.PermissionWriteSecret {
					writeRole = true
				}
				if strings.ToLower(action) == user.PermissionReadSecret {
					readRole = true
				}
			}
			for _, secretName := range role.ResourceNames {
				secret, ok := m.Secrets[secretName]
				if !ok {
					return fmt.Errorf("role %s: resource %s of type Secrets is not defined in manifest", roleName, secretName)
				}
				if !secret.UserDefined && writeRole {
					return fmt.Errorf("manifest specifies write permission for role %s and secret %s, but secret is not user-defined", roleName, secretName)
				}
				if !secret.Shared && !secret.UserDefined && readRole {
					return fmt.Errorf("manifest specifies read permission for role %s and per-marble-unique secret %s", roleName, secretName)
				}
			}
		default:
			return fmt.Errorf("unrecognized resource type: %s for role: %s", role, roleName)
		}
	}

	return nil
}

// PrivateKey is a wrapper for a binary private key, which we need for type differentiation in the PEM encoding function
type PrivateKey []byte

// PublicKey is a wrapper for a binary public key, which we need for type differentiation in the PEM encoding function
type PublicKey []byte

// Secret defines a structure for storing certificates & encryption keys
type Secret struct {
	Type        string
	Size        uint
	Shared      bool
	UserDefined bool
	Cert        Certificate
	ValidFor    uint
	Private     PrivateKey
	Public      PublicKey
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

// EncodeSecretDataToPem encodes a secret to an appropriate PEM block
func EncodeSecretDataToPem(data interface{}) (string, error) {
	var typ string
	var bytes []byte

	switch secret := data.(type) {
	case Certificate:
		typ, bytes = "CERTIFICATE", secret.Raw
	case PublicKey:
		typ, bytes = "PUBLIC KEY", secret
	case PrivateKey:
		typ, bytes = "PRIVATE KEY", secret
	default:
		return "", errors.New("invalid secret type")
	}

	if len(bytes) <= 0 {
		return "", errors.New("tried to parse secret with empty value")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: bytes})), nil
}

// EncodeSecretDataToHex encodes a secret to a hex string
func EncodeSecretDataToHex(data interface{}) (string, error) {
	raw, err := EncodeSecretDataToRaw(data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString([]byte(raw)), nil
}

// EncodeSecretDataToRaw encodes a secret to a raw byte string
func EncodeSecretDataToRaw(data interface{}) (string, error) {
	var raw []byte

	switch secret := data.(type) {
	case []byte:
		raw = secret
	case PrivateKey:
		raw = secret
	case PublicKey:
		raw = secret
	case Secret:
		raw = secret.Public
	case Certificate:
		raw = secret.Raw
	default:
		return "", errors.New("invalid secret type")
	}

	if len(raw) <= 0 {
		return "", errors.New("tried to parse secret with empty value")
	}
	return string(raw), nil
}

// EncodeSecretDataToBase64 encodes the byte value of a secret to a Base64 string
func EncodeSecretDataToBase64(data interface{}) (string, error) {
	raw, err := EncodeSecretDataToRaw(data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(raw)), nil
}

// ManifestTemplateFuncMap defines the functions which can be specified for secrets in the in go template format
var ManifestTemplateFuncMap = template.FuncMap{
	"pem":    EncodeSecretDataToPem,
	"hex":    EncodeSecretDataToHex,
	"raw":    EncodeSecretDataToRaw,
	"base64": EncodeSecretDataToBase64,
}

// CheckUpdate checks if the manifest is consistent and only contains supported values.
func (m Manifest) CheckUpdate(ctx context.Context, originalPackages map[string]quote.PackageProperties) error {
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
		if singlePackage.Debug || singlePackage.UniqueID != "" || singlePackage.SignerID != "" || singlePackage.ProductID != nil {
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
	}

	return nil
}

// UserSecret is a secret uploaded by a user
type UserSecret struct {
	Cert    Certificate
	Private PrivateKey
	Key     []byte
}

// ParseUserSecrets checks if a map of UserSecrets only contains supported values and parses them to a map of Secrets
func ParseUserSecrets(ctx context.Context, newSecrets map[string]UserSecret, originalSecrets map[string]Secret) (map[string]Secret, error) {
	if len(newSecrets) <= 0 {
		return nil, errors.New("no new secrets defined")
	}

	parsedSecrets := make(map[string]Secret)
	for secretName, singleSecret := range newSecrets {
		originalSecret, ok := originalSecrets[secretName]
		if !ok {
			return nil, errors.New("secret manifest specifies a secret which the original manifest does not contain")
		}
		if !originalSecret.UserDefined {
			return nil, fmt.Errorf("secret %s is not writeable", secretName)
		}

		// check correctness of the supplied secrets
		switch originalSecret.Type {
		case "symmetric-key":
			// verify the length specified in the original manifest is constant
			if originalSecret.Size == 0 || originalSecret.Size%8 != 0 {
				return nil, fmt.Errorf("invalid secret size: %s", secretName)
			}
			// make sure the supplied secret is actually of the specified length
			if len(singleSecret.Key) != int(originalSecret.Size/8) {
				return nil, fmt.Errorf("declared size and actual size don't match: %s", secretName)
			}
			// make sure only a symmetric key was supplied
			if singleSecret.Cert.Raw != nil || singleSecret.Private != nil {
				return nil, fmt.Errorf("secret %s is set to be of type symmetric-key but specified values for a certificate", secretName)
			}
			parsedSecret := originalSecret
			parsedSecret.Private = singleSecret.Key
			parsedSecret.Public = singleSecret.Key
			parsedSecrets[secretName] = parsedSecret
		case "cert-rsa", "cert-ecdsa", "cert-ed25519":
			// make sure only certificate data was supplied
			if singleSecret.Key != nil {
				return nil, fmt.Errorf("secret %s is set to be of type %s but specified values for a symmetric-key", secretName, originalSecret.Type)
			}
			// correctnes of the private key is not checked here, and can even be left empty
			// if it is left empty trying to start a marble using the key will fail
			var err error
			parsedSecret := originalSecret
			parsedSecret.Cert = singleSecret.Cert
			parsedSecret.Private = singleSecret.Private
			parsedSecret.Public, err = x509.MarshalPKIXPublicKey(singleSecret.Cert.PublicKey)
			if err != nil {
				return nil, err
			}
			parsedSecrets[secretName] = parsedSecret
		case "plain":
			// make sure only a key data was supplied
			if singleSecret.Cert.Raw != nil || singleSecret.Private != nil {
				return nil, fmt.Errorf("secret %s is set to be of type symmetric-key but specified values for a certificate", secretName)
			}
			parsedSecret := originalSecret
			parsedSecret.Private = singleSecret.Key
			parsedSecret.Public = singleSecret.Key
			parsedSecrets[secretName] = parsedSecret
		}

	}
	return parsedSecrets, nil
}

func warnOrFailForMissingValue(debugMode bool, parameter string, packageName string, zaplogger *zap.Logger) error {
	if debugMode {
		zaplogger.Warn("Manifest misses value in package declaration. This is not accepted in non-debug mode, please check your configuration.", zap.String("parameter", parameter), zap.String("packageName", packageName))
		return nil
	}

	return fmt.Errorf("manifest misses value for %s in package %s", parameter, packageName)
}
