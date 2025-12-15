/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package keyrelease

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/distributor"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	dstore "github.com/edgelesssys/marblerun/coordinator/store/distributed"
	"github.com/edgelesssys/marblerun/util"
	"go.uber.org/zap"
)

const (
	wrappingKeySize = 4096
)

// rootCerts holds root certificates for TLS connections with Azure services.
var rootCerts *x509.CertPool

type distributedSealer interface {
	dstore.Sealer
	distributor.KeyGenerator
}

// KeyReleaser releases keys from an Azure Key Vault using Secure Key Release.
type KeyReleaser struct {
	distributedSealer

	enabled       bool
	hsmSealingKey []byte
	keyName       string
	keyVersion    string
	maaURL        string
	vaultURL      string
	client        *azkeys.Client

	log *zap.Logger
}

// New creates a new [KeyReleaser] with credentials from environment variables.
func New(sealer seal.Sealer, log *zap.Logger) (*KeyReleaser, error) {
	if err := os.Setenv(strings.TrimPrefix(constants.EnvAzureClientID, "EDG_"), os.Getenv(constants.EnvAzureClientID)); err != nil {
		return nil, err
	}
	if err := os.Setenv(strings.TrimPrefix(constants.EnvAzureTenantID, "EDG_"), os.Getenv(constants.EnvAzureTenantID)); err != nil {
		return nil, err
	}
	if err := os.Setenv(strings.TrimPrefix(constants.EnvAzureClientSecret, "EDG_"), os.Getenv(constants.EnvAzureClientSecret)); err != nil {
		return nil, err
	}
	vaultURL := os.Getenv(constants.EnvAzureHSMVaultURL)
	keyName := os.Getenv(constants.EnvAzureHSMKeyName)
	keyVersion := os.Getenv(constants.EnvAzureHSMKeyVersion)
	maaURL := util.Getenv(constants.EnvMAAURL, "https://shareduks.uks.attest.azure.net") // fallback to uk-south attestation provider

	if err := initEnclave(); err != nil {
		return nil, err
	}

	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: azureTLSClient(),
		},
	})
	if err != nil {
		return nil, err
	}

	client, err := azkeys.NewClient(vaultURL, cred, &azkeys.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: azureTLSClient(),
		},
	})
	if err != nil {
		return nil, err
	}

	castSealer, ok := sealer.(distributedSealer)
	if !ok {
		castSealer = &stubDistributedSealer{
			Sealer: sealer,
			log:    log,
		}
	}

	return &KeyReleaser{
		distributedSealer: castSealer,
		keyName:           keyName,
		keyVersion:        keyVersion,
		maaURL:            maaURL,
		vaultURL:          vaultURL,
		client:            client,
		enabled:           false,
		log:               log,
	}, nil
}

// SetEnabled enables the wrapping and unwrapping of keys using an HSM key from Azure Key Vault.
func (k *KeyReleaser) SetEnabled(enabled bool) {
	k.enabled = enabled
}

// azureTLSClient returns an HTTP client with access to system root CAs.
func azureTLSClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: rootCerts},
		},
	}
}

type stubDistributedSealer struct {
	seal.Sealer
	log *zap.Logger
}

func (s *stubDistributedSealer) SealKEK(context.Context, seal.Mode) error {
	s.log.Error("Stub distributed sealer: SealKEK called")
	return errors.New("unsupported function called")
}

func (s *stubDistributedSealer) SetSealMode(seal.Mode) {
	s.log.Error("Stub distributed sealer: SetSealMode called")
}

func (s *stubDistributedSealer) ExportKeyEncryptionKey(context.Context) ([]byte, error) {
	s.log.Error("Stub distributed sealer: ExportKeyEncryptionKey called")
	return nil, errors.New("unsupported function called")
}

func (s *stubDistributedSealer) SetKeyEncryptionKey(context.Context, []byte) error {
	s.log.Error("Stub distributed sealer: SetKeyEncryptionKey called")
	return errors.New("unsupported function called")
}
