/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package manifest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/stretchr/testify/require"
)

// Keys for default manifest generation.
const (
	DefaultPackage            = "package1"
	DefaultMarble             = "marble1"
	DefaultUser               = "alice"
	DefaultUser2              = "bob"
	DefaultUserSecret         = "UserData"
	DefaultUpdateManifestRole = "UpdateManifest"
	DefaultUpdatePackageRole  = "UpdatePackage1"
	DefaultAccessUserDataRole = "AccessUserData"
)

// Manifest defines the manifest file.
type Manifest struct {
	Packages     map[string]PackageProperties `json:"Packages,omitempty"`
	Marbles      map[string]manifest.Marble   `json:"Marbles,omitempty"`
	Users        map[string]manifest.User     `json:"Users,omitempty"`
	Secrets      map[string]Secret            `json:"Secrets,omitempty"`
	RecoveryKeys map[string]string            `json:"RecoveryKeys,omitempty"`
	Roles        map[string]manifest.Role     `json:"Roles,omitempty"`
	TLS          map[string]manifest.TLStag   `json:"TLS,omitempty"`
	Config       manifest.Config              `json:"Config,omitzero"`
}

// PackageProperties is an alternative to the manifest.PackageProperties struct,
// which allows for easier marshalling and handling of values.
type PackageProperties struct {
	Debug           bool   `json:"Debug,omitempty"`
	UniqueID        string `json:"UniqueID,omitempty"`
	SignerID        string `json:"SignerID,omitempty"`
	ProductID       uint64 `json:"ProductID,omitempty"`
	SecurityVersion uint   `json:"SecurityVersion,omitempty"`
}

// Secret is an alternative to the manifest.Secret struct,
// which allows marshalling of the Cert field.
type Secret struct {
	Type        string         `json:"Type,omitempty"`
	Size        uint           `json:"Size,omitempty"`
	Shared      bool           `json:"Shared,omitempty"`
	UserDefined bool           `json:"UserDefined,omitempty"`
	ValidFor    uint           `json:"ValidFor,omitempty"`
	Cert        map[string]any `json:"Cert,omitempty"`
}

// defaultManifest returns a manifest using the given user certificate and key.
func defaultManifest(userCertPEM []byte, recoveryKeyPEM []byte, defaultPackage PackageProperties) Manifest {
	return Manifest{
		Packages: map[string]PackageProperties{
			DefaultPackage: defaultPackage,
		},
		Marbles: map[string]manifest.Marble{
			DefaultMarble: {
				Package: DefaultPackage,
				Parameters: manifest.Parameters{
					Argv: []string{"marble", "serve-no-client-auth"},
					Files: map[string]manifest.File{
						"/dev/attestation/protected_files_key":          {Data: "{{ hex .Secrets.ProtectedFilesKey }}", Encoding: "string"},
						"/data/marble.crt":                              {Data: "{{ pem .MarbleRun.MarbleCert.Cert }}", Encoding: "string"},
						"/data/marble.key":                              {Data: "{{ pem .MarbleRun.MarbleCert.Private }}", Encoding: "string"},
						"/data/ca.crt":                                  {Data: "{{ pem .MarbleRun.RootCA.Cert }}", Encoding: "string"},
						"/dev/attestation/previous_protected_files_key": {Data: "{{ hex .Previous.Secrets.ProtectedFilesKey }}", Encoding: "string"},
						"/data/previous_ca.crt":                         {Data: "{{ pem .Previous.MarbleRun.RootCA.Cert }}", Encoding: "string"},
					},
				},
			},
		},
		Secrets: map[string]Secret{
			"ProtectedFilesKey": {
				Type:   manifest.SecretTypeSymmetricKey,
				Size:   128,
				Shared: true,
			},
			DefaultUserSecret: {
				Type:        manifest.SecretTypePlain,
				UserDefined: true,
			},
		},
		Users: map[string]manifest.User{
			DefaultUser: {
				Certificate: string(userCertPEM),
				Roles:       []string{DefaultUpdateManifestRole, DefaultUpdatePackageRole, DefaultAccessUserDataRole},
			},
		},
		RecoveryKeys: map[string]string{
			DefaultUser: string(recoveryKeyPEM),
		},
		Roles: map[string]manifest.Role{
			DefaultUpdateManifestRole: {
				ResourceType: "Manifest",
				Actions:      []string{"UpdateManifest"},
			},
			DefaultUpdatePackageRole: {
				ResourceType:  "Packages",
				ResourceNames: []string{DefaultPackage},
				Actions:       []string{"UpdateSecurityVersion"},
			},
			DefaultAccessUserDataRole: {
				ResourceType:  "Secrets",
				ResourceNames: []string{DefaultUserSecret},
				Actions:       []string{"ReadSecret", "WriteSecret"},
			},
		},
	}
}

// GenerateCertificate creates a certificate using the provided private key for testing.
func GenerateCertificate(t *testing.T, privKey *rsa.PrivateKey) (cert []byte) {
	t.Helper()

	// Create some demo certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(42),
		IsCA:         false,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
	}

	testCertRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCertRaw})
	return pemData
}

// GenerateKey creates a private key and returns the public key in PEM format.
func GenerateKey(t *testing.T) (publicKeyPem []byte, privateKey *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pkixPublicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkixPublicKey,
	}

	return pem.EncodeToMemory(publicKeyBlock), key
}
