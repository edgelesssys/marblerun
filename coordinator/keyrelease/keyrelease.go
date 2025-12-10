/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package keyrelease

import (
	"context"
	"crypto/tls"
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

	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: insecureClient(), // Skip TLS verification. There is no need for a trusted connection
		},
	})
	if err != nil {
		return nil, err
	}

	client, err := azkeys.NewClient(vaultURL, cred, &azkeys.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: insecureClient(), // Skip TLS verification. There is no need for a trusted connection
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
		client:            client,
		enabled:           false,
		log:               log,
	}, nil
}

// Enable the wrapping and unwrapping of keys using an HSM key from Azure Key Vault.
func (k *KeyReleaser) Enable() {
	k.enabled = true
}

// insecureClient returns an HTTP client that skips TLS certificate verification.
// This is used to bypass the fact that the enclave does not have a set of Root CAs.
func insecureClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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
