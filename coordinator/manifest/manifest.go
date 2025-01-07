/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package manifest

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"text/template"

	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/user"
	"github.com/edgelesssys/marblerun/util"
	"go.uber.org/zap"
)

const (
	// SecretTypeCertECDSA defines the type of a secret containing an ECDSA certificate.
	SecretTypeCertECDSA = "cert-ecdsa"
	// SecretTypeCertED25519 defines the type of a secret containing an ED25519 certificate.
	SecretTypeCertED25519 = "cert-ed25519"
	// SecretTypeCertRSA defines the type of a secret containing an RSA certificate.
	SecretTypeCertRSA = "cert-rsa"
	// SecretTypeSymmetricKey defines the type of a secret containing a symmetric key.
	SecretTypeSymmetricKey = "symmetric-key"
	// SecretTypePlain defines the type of a secret containing arbitrary data.
	SecretTypePlain = "plain"
)

const (
	// FeatureSignQuoteEndpoint enables the /sign-quote endpoint.
	// This endpoint allows to verify an SGX quote and sign the result with the Coordinator's private key.
	FeatureSignQuoteEndpoint = "SignQuoteEndpoint"

	// FeatureMonotonicCounter enables the monotonic counter feature and the /monotonic-counter endpoint.
	FeatureMonotonicCounter = "MonotonicCounter"
)

// Manifest defines the rules of a MarbleRun deployment.
type Manifest struct {
	// Packages contains the allowed enclaves and their properties.
	Packages map[string]quote.PackageProperties
	// Infrastructures contains the allowed infrastructure providers and their properties.
	Infrastructures map[string]quote.InfrastructureProperties
	// Marbles contains the allowed services with their corresponding enclave and configuration parameters.
	Marbles map[string]Marble
	// Users contains user definitions, including certificates used for authentication and permissions.
	Users map[string]User
	// Secrets holds user-specified secrets, which should be generated and later on stored in a marble (if not shared) or in the core (if shared).
	Secrets map[string]Secret
	// RecoveryKeys holds one or multiple RSA public keys to encrypt multiple secrets, which can be used to decrypt the sealed state again in case the encryption key on disk was corrupted somehow.
	RecoveryKeys map[string]string
	// Roles contains role definitions to manage permissions across the MarbleRun mesh
	Roles map[string]Role
	// TLS contains tags which can be assigned to Marbles to specify which connections should be elevated to TLS
	TLS map[string]TLStag
	// Config contains optional configuration for the Coordinator.
	Config Config
}

// Config contains optional configuration for the Coordinator.
type Config struct {
	// SealMode specifies how the data should be sealed. Can be "ProductKey" (default if empty), "UniqueKey", or "Disabled".
	SealMode string
	// FeatureGates is a list of additional features to enable on the Coordinator.
	FeatureGates []string
	// UpdateThreshold is the amount of acknowledgements required to perform a multi party manifest update.
	// If set to 0, all users with the update permission are required to acknowledge an update before it is applied.
	UpdateThreshold uint
}

// Marble describes a service in the mesh that should be handled and verified by the Coordinator.
type Marble struct {
	// Package references one of the allowed enclaves in the manifest.
	Package string
	// MaxActivations allows to limit the number of marbles of a kind.
	MaxActivations uint
	// Parameters contains lists for files, environment variables and commandline arguments that should be passed to the application.
	// Placeholder variables are supported for specific assets of the marble's activation process.
	Parameters Parameters
	// TLS holds a list of tags which are specified in the manifest
	TLS []string
	// DisableSecretBinding causes the Coordinator to not include the Marble's name for secret derivation.
	// Effectively, this enforces the same behavior of the Coordinator previous to version 1.6.0.
	DisableSecretBinding bool
}

// Equal returns true if two Marble definitions are equal.
func (m Marble) Equal(other Marble) bool {
	if !util.SliceEqualElements(m.TLS, other.TLS) {
		return false
	}

	return m.Package == other.Package &&
		m.MaxActivations == other.MaxActivations &&
		m.Parameters.Equal(other.Parameters) &&
		m.DisableSecretBinding == other.DisableSecretBinding
}

// Parameters contains lists for files, environment variables and commandline arguments that should be passed to an application.
type Parameters struct {
	Files map[string]File
	Env   map[string]File
	Argv  []string
}

// Equal returns true if two Parameters are equal.
// This checks if all Files and Env definitions are equal,
// and if the Argv lists are in the same order, and contain the same arguments.
func (p Parameters) Equal(other Parameters) bool {
	if len(p.Argv) != len(other.Argv) {
		return false
	}
	for i := range p.Argv {
		if p.Argv[i] != other.Argv[i] {
			return false
		}
	}

	if len(p.Files) != len(other.Files) {
		return false
	}
	for k, v := range p.Files {
		if !v.Equal(other.Files[k]) {
			return false
		}
	}

	if len(p.Env) != len(other.Env) {
		return false
	}
	for k, v := range p.Env {
		if !v.Equal(other.Env[k]) {
			return false
		}
	}

	return true
}

// File defines data, encoding type, and if data contains templates for a File or Env variable.
type File struct {
	// Data is the data to be saved as a file or environment variable.
	Data string
	// Encoding is the initial encoding of Data (as it is written in the manifest). One of {'string', 'base64', 'hex'}.
	Encoding string
	// NoTemplates specifies if Data contains templates which should be filled with information by the Coordinator.
	NoTemplates bool
}

// Equal returns true if two File definitions are equal.
func (f File) Equal(other File) bool {
	return f.Data == other.Data &&
		f.Encoding == other.Encoding &&
		f.NoTemplates == other.NoTemplates
}

// MarshalJSON implements the json.Marshaler interface.
func (f File) MarshalJSON() ([]byte, error) {
	tmp := struct {
		Data        string
		Encoding    string
		NoTemplates bool
	}{
		Encoding:    f.Encoding,
		NoTemplates: f.NoTemplates,
	}

	switch e := f.Encoding; {
	case strings.ToLower(e) == "string":
		// just marshal f as is
		tmp.Data = f.Data
	case strings.ToLower(e) == "base64":
		// encode the Data field back to base64
		tmp.Data = base64.StdEncoding.EncodeToString([]byte(f.Data))
	case strings.ToLower(e) == "hex":
		tmp.Data = hex.EncodeToString([]byte(f.Data))
	default:
		return nil, fmt.Errorf("unknown encoding type: %s", f.Encoding)
	}
	return json.Marshal(tmp)
}

// UnmarshalJSON implements the json.Marshaler interface.
func (f *File) UnmarshalJSON(data []byte) error {
	// a File or Env in the manifest can be defined two ways:
	//   1. as a single string: "<name>": "<content>"
	//   2. as a struct with Data, Encoding, and NoTemplate fields: "<name>": {"Data": "<data>", "Encoding": "<encoding>", "NoTemplates": <true/false>}

	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	switch t := v.(type) {
	case string:
		// File was defined using a single string. Set default value for NoTemplates and Encoding to "string", since we don't want to make assumptions about possible data encodings
		f.Data = t
		f.Encoding = "string"
		f.NoTemplates = false
		return nil
	case interface{}:
		// To avoid infinite recursion, try to unmarshal into a struct with the same data types as File
		var vF struct {
			Data        string
			Encoding    string
			NoTemplates bool
		}
		if err := json.Unmarshal(data, &vF); err != nil {
			return err
		}

		f.Encoding = vF.Encoding
		if f.Encoding == "" {
			f.Encoding = "string"
		}

		// decode Data if it was encoded
		switch e := f.Encoding; {
		case strings.ToLower(e) == "string":
			f.Data = vF.Data
		case strings.ToLower(e) == "base64":
			decoded, err := base64.StdEncoding.DecodeString(vF.Data)
			if err != nil {
				return err
			}
			f.Data = string(decoded)
		case strings.ToLower(e) == "hex":
			decoded, err := hex.DecodeString(vF.Data)
			if err != nil {
				return err
			}
			f.Data = string(decoded)
		default:
			return fmt.Errorf("unknown encoding type: %s", f.Encoding)
		}

		f.NoTemplates = vF.NoTemplates
	default:
		return fmt.Errorf("got: %t, expected: string or interface", t)
	}

	return nil
}

// TLStag describes which entries should be used to determine the ttls connections of a marble.
type TLStag struct {
	// Outgoing holds a list of all outgoing addresses that should be elevated to TLS.
	Outgoing []TLSTagEntry
	// Incoming holds a list of all incoming addresses that should be elevated to TLS.
	Incoming []TLSTagEntry
}

// Equal checks if two TLStags are equal.
func (t TLStag) Equal(other TLStag) bool {
	if len(t.Outgoing) != len(other.Outgoing) {
		return false
	}
	if len(t.Incoming) != len(other.Incoming) {
		return false
	}

	otherIncoming := make([]TLSTagEntry, len(other.Incoming))
	copy(otherIncoming, other.Incoming)
	otherOutgoing := make([]TLSTagEntry, len(other.Outgoing))
	copy(otherOutgoing, other.Outgoing)
	tOutgoing := make([]TLSTagEntry, len(t.Outgoing))
	copy(tOutgoing, t.Outgoing)
	tIncoming := make([]TLSTagEntry, len(t.Incoming))
	copy(tIncoming, t.Incoming)

	sortTLSTagEntries(otherIncoming)
	sortTLSTagEntries(otherOutgoing)
	sortTLSTagEntries(tIncoming)
	sortTLSTagEntries(tOutgoing)

	for i, tag := range tOutgoing {
		if !tag.Equal(otherOutgoing[i]) {
			return false
		}
	}
	for i, tag := range tIncoming {
		if !tag.Equal(otherIncoming[i]) {
			return false
		}
	}

	return true
}

func sortTLSTagEntries(entries []TLSTagEntry) {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Addr == entries[j].Addr {
			return entries[i].Port < entries[j].Port
		}

		return entries[i].Addr < entries[j].Addr
	})
}

// TLSTagEntry describes one connection which should be elevated to ttls.
type TLSTagEntry struct {
	Port              string
	Addr              string
	Cert              string
	DisableClientAuth bool
}

// Equal returns true if two TLSTagEntries are equal.
func (t TLSTagEntry) Equal(other TLSTagEntry) bool {
	return t.Addr == other.Addr && t.Port == other.Port && t.Cert == other.Cert && t.DisableClientAuth == other.DisableClientAuth
}

// User describes the attributes of a MarbleRun user.
type User struct {
	// Certificate is the TLS certificate used by the user for authentication.
	Certificate string
	// Roles is a list of roles granting permissions to the user.
	Roles []string
}

// Role describes a set of actions permitted for a specific set of resources.
type Role struct {
	// ResourceType is the type of the affected resources.
	ResourceType string
	// ResourceNames is a list of names of type ResourceType.
	ResourceNames []string
	// Actions are the allowed actions for the defined resources.
	Actions []string
}

// Check checks if the manifest is consistent.
func (m Manifest) Check(zaplogger *zap.Logger) error {
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
				return fmt.Errorf("manifest specifies both UniqueID *and* SignerID/ProductID/SecurityVersion in package %s", marble.Package)
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

	uniqueUsers := make(map[string]string)
	for userName, user := range m.Users {
		if len(user.Certificate) <= 0 {
			return fmt.Errorf("manifest does not contain a certificate for user %s", userName)
		}
		for _, role := range user.Roles {
			if _, ok := m.Roles[role]; !ok {
				return fmt.Errorf("manifest specifies role %s for user %s, but role does not exist", role, userName)
			}
		}

		// Check if user certificate is unique
		if otherUser, ok := uniqueUsers[user.Certificate]; ok {
			return fmt.Errorf("manifest contains the same certificate for users %s and %s", userName, otherUser)
		}
		uniqueUsers[user.Certificate] = userName
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
					return fmt.Errorf("unknown action: %s for type Packages in role: %s", action, roleName)
				}
			}
		case "Secrets":
			var writeRole bool
			var readRole bool
			for _, action := range role.Actions {
				if !(strings.ToLower(action) == user.PermissionWriteSecret || strings.ToLower(action) == user.PermissionReadSecret) {
					return fmt.Errorf("unknown action: %s for type Secrets in role: %s", action, roleName)
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
		case "Manifest":
			if len(role.ResourceNames) != 0 {
				return fmt.Errorf("role %s: resource names are not allowed for type Manifest", roleName)
			}
			for _, action := range role.Actions {
				if !(strings.ToLower(action) == user.PermissionUpdateManifest) {
					return fmt.Errorf("unknown action: %s for type Manifest in role: %s", action, roleName)
				}
			}
		default:
			return fmt.Errorf("unrecognized resource type: %s for role: %s", role, roleName)
		}
	}

	for name, s := range m.Secrets {
		switch s.Type {
		case SecretTypePlain, SecretTypeSymmetricKey:
			continue
		case SecretTypeCertRSA, SecretTypeCertED25519, SecretTypeCertECDSA:
			if !s.Cert.NotAfter.IsZero() && (s.ValidFor != 0) {
				return fmt.Errorf("ambiguous certificate validity duration for secret: %s, both NotAfter and ValidFor are specified", name)
			}
		default:
			return fmt.Errorf("unknown type: %s for secret: %s", s.Type, name)
		}
	}

	var manifestUpdaters int
	for _, mrUser := range m.Users {
		for _, roleName := range mrUser.Roles {
			if m.Roles[roleName].ResourceType == "Manifest" && strings.ToLower(m.Roles[roleName].Actions[0]) == user.PermissionUpdateManifest {
				manifestUpdaters++
				break // Avoid counting the same user multiple times if they are assigned more than one role with update permission
			}
		}
	}
	if manifestUpdaters < int(m.Config.UpdateThreshold) {
		return fmt.Errorf("not enough users with manifest update permissions (%d) to meet the threshold of %d", manifestUpdaters, m.Config.UpdateThreshold)
	}

	switch m.Config.SealMode {
	case "", "ProductKey", "UniqueKey", "Disabled":
	default:
		return fmt.Errorf("unknown seal mode: %s", m.Config.SealMode)
	}

	for _, feature := range m.Config.FeatureGates {
		switch feature {
		case FeatureSignQuoteEndpoint, FeatureMonotonicCounter:
		default:
			return fmt.Errorf("unknown feature gate: %s", feature)
		}
	}

	return nil
}

// TemplateDryRun performs a dry run for Files and Env declarations in a manifest.
func (m Manifest) TemplateDryRun(secrets map[string]Secret) error {
	templateSecrets := SecretsWrapper{
		Secrets: secrets,
		MarbleRun: ReservedSecrets{
			RootCA: Secret{
				Cert: Certificate{Raw: []byte{0x41}},
			},
			MarbleCert: Secret{
				Cert:    Certificate{Raw: []byte{0x41}},
				Public:  []byte{0x41},
				Private: []byte{0x41},
			},
			CoordinatorRoot: Secret{
				Cert: Certificate{Raw: []byte{0x41}},
			},
			CoordinatorIntermediate: Secret{
				Cert: Certificate{Raw: []byte{0x41}},
			},
		},
	}
	// make sure templates in file/env declarations can actually be executed
	for marbleName, marble := range m.Marbles {
		for fileName, file := range marble.Parameters.Files {
			if !file.NoTemplates {
				if err := checkTemplate(file.Data, ManifestFileTemplateFuncMap, templateSecrets); err != nil {
					return fmt.Errorf("in Marble %s: file %s: %w", marbleName, fileName, err)
				}
			}
		}
		for envName, env := range marble.Parameters.Env {
			// make sure environment variables don't contain NULL bytes, we perform another check at runtime to catch NULL bytes in secrets
			if strings.Contains(env.Data, string([]byte{0x00})) {
				return fmt.Errorf("in Marble %s: env variable: %s: content contains null bytes", marbleName, envName)
			}
			if !env.NoTemplates {
				if err := checkTemplate(env.Data, ManifestEnvTemplateFuncMap, templateSecrets); err != nil {
					return fmt.Errorf("in Marble %s: env variable %s: %w", marbleName, envName, err)
				}
			}
		}
	}

	return nil
}

// GenerateUsers creates users and assigns permissions from the manifest.
func (m Manifest) GenerateUsers() ([]*user.User, error) {
	users := make([]*user.User, 0, len(m.Users))
	for name, userData := range m.Users {
		block, _ := pem.Decode([]byte(userData.Certificate))
		if block == nil {
			return nil, fmt.Errorf("received invalid certificate for user %s", name)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		newUser := user.NewUser(name, cert)
		for _, assignedRole := range userData.Roles {
			for _, action := range m.Roles[assignedRole].Actions {
				// correctness of roles has been verified by manifest.Check()
				newUser.Assign(user.NewPermission(strings.ToLower(action), m.Roles[assignedRole].ResourceNames))
			}
		}
		users = append(users, newUser)
	}
	return users, nil
}

// IsUpdateManifest returns true if the manifest specifies only packages.
// The Manifest still needs to be check for consistency, e.g. by calling CheckUpdate.
func (m Manifest) IsUpdateManifest() bool {
	return len(m.Infrastructures) == 0 && len(m.Marbles) == 0 &&
		len(m.Users) == 0 && len(m.RecoveryKeys) == 0 &&
		len(m.Roles) == 0 && len(m.Secrets) == 0 &&
		len(m.TLS) == 0
}

// CheckUpdate checks if the manifest is consistent and only contains supported values.
func (m Manifest) CheckUpdate(originalPackages map[string]quote.PackageProperties) error {
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
			return errors.New("update manifest does not specify a SecurityVersion to update")
		}

		// Check based on the original manifest
		if originalPackages[packageName].SecurityVersion != nil && *singlePackage.SecurityVersion < *originalPackages[packageName].SecurityVersion {
			return errors.New("update manifest tries to downgrade SecurityVersion of the original manifest")
		}
	}

	return nil
}

// ReservedSecrets is a tuple of secrets reserved for a single Marble.
type ReservedSecrets struct {
	RootCA                  Secret
	MarbleCert              Secret
	CoordinatorRoot         Secret
	CoordinatorIntermediate Secret
}

// SecretsWrapper is used to define the "MarbleRun" prefix when mentioned in a manifest.
type SecretsWrapper struct {
	MarbleRun ReservedSecrets
	Secrets   map[string]Secret
}

// PrivateKey is a symmetric key or an asymmetric private key in PKCS #8, ASN.1 DER form,
// typically created by calling [x509.MarshalPKCS8PrivateKey].
type PrivateKey []byte

// PublicKey is a symmetric key or an asymmetric public key in PKIX, ASN.1 DER form,
// typically created by calling [x509.MarshalPKIXPublicKey].
type PublicKey []byte

// Secret is the structure of a secret managed by MarbleRun.
type Secret struct {
	// Type of the secret.
	// One of {"cert-ecdsa", "cert-ed25519", "cert-rsa", "symmetric-key", "plain"}.
	Type string
	// Size of the key in bits.
	// For Type "symmetric-key", this needs to be a multiple of 8.
	// For Type "cert-ecdsa", this needs to map to a curve supported by Go's crypto library, currently: 224, 256, 384, or 521.
	// For "cert-ed25519", this should be omitted.
	Size uint
	// Shared specifies whether this secret is shared across all marbles,
	// or if it is unique to each marble.
	Shared bool
	// UserDefined specifies whether a secret should be generated by the MarbleRun (false),
	// or if it will be uploaded by a user at a later point (true).
	UserDefined bool
	// Cert is a X.509 certificate.
	Cert Certificate
	// ValidFor is the validity of a certificate in days.
	ValidFor uint
	// Private is a private key of a certificate, or a symmetric key.
	Private PrivateKey
	// Public is a public key of a certificate, or a symmetric key.
	Public PublicKey
}

// Equal returns true if the two secrets are equal.
// This checks if the secrets are equal in all fields.
func (s Secret) Equal(other Secret) bool {
	cert := x509.Certificate(s.Cert)
	otherCert := x509.Certificate(other.Cert)

	return s.EqualDefinition(other) &&
		cert.Equal(&otherCert) &&
		bytes.Equal(s.Private, other.Private) &&
		bytes.Equal(s.Public, other.Public)
}

// EqualDefinition returns true if the two secrets are equal.
// This only checks if the secret definitions are equal,
// i.e. if the secrets are equal in all fields except for the actual secret data.
func (s Secret) EqualDefinition(other Secret) bool {
	return s.Type == other.Type &&
		s.Size == other.Size &&
		s.Shared == other.Shared &&
		s.UserDefined == other.UserDefined &&
		s.ValidFor == other.ValidFor
}

// Certificate is a x509.Certificate.
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

// EncodeSecretDataToPem encodes a secret to an appropriate PEM block.
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
	case nil:
		return "", errors.New("secret does not exist")
	default:
		return "", errors.New("invalid secret type for pem encoding")
	}

	if len(bytes) <= 0 {
		return "", errors.New("tried to parse secret with empty value")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: bytes})), nil
}

// EncodeSecretDataToHex encodes a secret to a hex string.
func EncodeSecretDataToHex(data interface{}) (string, error) {
	raw, err := EncodeSecretDataToRaw(data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString([]byte(raw)), nil
}

// EncodeSecretDataToRaw encodes a secret to a raw byte string.
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
	case nil:
		return "", errors.New("secret does not exist")
	default:
		return "", errors.New("invalid secret type")
	}

	if len(raw) <= 0 {
		return "", errors.New("tried to parse secret with empty value")
	}
	return string(raw), nil
}

// EncodeSecretDataToBase64 encodes the byte value of a secret to a Base64 string.
func EncodeSecretDataToBase64(data interface{}) (string, error) {
	raw, err := EncodeSecretDataToRaw(data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(raw)), nil
}

// EncodeSecretDataToString encodes secrets to C type strings (no NULL bytes allowed as part of the string).
func EncodeSecretDataToString(data interface{}) (string, error) {
	switch secret := data.(type) {
	case Secret:
		if secret.Type != SecretTypePlain {
			return "", errors.New("only secrets of type plain are allowed to use string encoding for environment variables")
		}
		if strings.Contains(string(secret.Public), string([]byte{0x00})) {
			return "", errors.New("secret contains null bytes")
		}
		return EncodeSecretDataToRaw(data)
	case nil:
		return "", errors.New("secret does not exist")
	default:
		return "", errors.New("only secrets of type plain are allowed to use string encoding for environment variables")
	}
}

// ManifestFileTemplateFuncMap defines the functions which can be specified for secret injections into files in the in Go template format.
var ManifestFileTemplateFuncMap = template.FuncMap{
	"pem":    EncodeSecretDataToPem,
	"hex":    EncodeSecretDataToHex,
	"raw":    EncodeSecretDataToRaw,
	"base64": EncodeSecretDataToBase64,
}

// ManifestEnvTemplateFuncMap defines the functions which can be specified for secret injections into Env variables in the Go template format.
var ManifestEnvTemplateFuncMap = template.FuncMap{
	"pem":    EncodeSecretDataToPem,
	"hex":    EncodeSecretDataToHex,
	"string": EncodeSecretDataToString,
	"base64": EncodeSecretDataToBase64,
}

// UserSecret is a secret uploaded by a user.
// Only Key, or Cert and Private may be set at the same time.
type UserSecret struct {
	// Cert is a certificate uploaded by a user.
	Cert Certificate
	// Private is a private key of a certificate uploaded by a user.
	Private PrivateKey
	// Key is a symmetric key or arbitrary binary data uploaded by a user.
	Key []byte
}

// ParseUserSecrets checks if a map of UserSecrets only contains supported values and parses them to a map of Secrets.
func ParseUserSecrets(newSecrets map[string]UserSecret, originalSecrets map[string]Secret) (map[string]Secret, error) {
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
		case SecretTypeSymmetricKey:
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
		case SecretTypeCertRSA, SecretTypeCertECDSA, SecretTypeCertED25519:
			// make sure only certificate data was supplied
			if singleSecret.Key != nil {
				return nil, fmt.Errorf("secret %s is set to be of type %s but specified values for a symmetric-key", secretName, originalSecret.Type)
			}
			// correctness of the private key is not checked here, and can even be left empty
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
		case SecretTypePlain:
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

// checkTemplate executes the template with the given data and returns an error if the template is invalid.
func checkTemplate(data string, tplFunc template.FuncMap, secrets SecretsWrapper) error {
	tpl, err := template.New("data").Funcs(tplFunc).Parse(data)
	if err != nil {
		return err
	}
	return tpl.Execute(&bytes.Buffer{}, secrets)
}
