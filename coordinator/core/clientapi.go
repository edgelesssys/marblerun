// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ClientCore provides the core functionality for the client. It can be used by e.g. a http server
type ClientCore interface {
	SetManifest(ctx context.Context, rawManifest []byte) (recoverySecretMap map[string][]byte, err error)
	GetCertQuote(ctx context.Context) (cert string, certQuote []byte, err error)
	GetManifestSignature(ctx context.Context) (manifestSignature []byte)
	GetStatus(ctx context.Context) (statusCode int, status string, err error)
	Recover(ctx context.Context, encryptionKey []byte) (int, error)
	VerifyAdmin(ctx context.Context, clientCerts []*x509.Certificate) bool
	UpdateManifest(ctx context.Context, rawUpdateManifest []byte) error
}

// SetManifest sets the manifest, once and for all
//
// rawManifest is the manifest of type Manifest in JSON format.
func (c *Core) SetManifest(ctx context.Context, rawManifest []byte) (map[string][]byte, error) {
	defer c.mux.Unlock()
	if err := c.requireState(stateAcceptingManifest, stateRecovery); err != nil {
		return nil, err
	}

	var manifest manifest.Manifest
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		return nil, err
	}
	if err := manifest.Check(ctx, c.zaplogger); err != nil {
		return nil, err
	}

	intermediateCert, err := c.store.getCertificate("intermediate")
	if err != nil {
		return nil, err
	}
	intermediatePrivK, err := c.store.getPrivK("intermediate")
	if err != nil {
		return nil, err
	}

	// Generate shared secrets specified in manifest
	secrets, err := c.generateSecrets(ctx, manifest.Secrets, uuid.Nil, intermediateCert, intermediatePrivK)
	if err != nil {
		c.zaplogger.Error("Could not generate specified secrets for the given manifest.", zap.Error(err))
		return nil, err
	}

	// Set encryption key & generate recovery data
	encryptionKey, err := c.recovery.GenerateEncryptionKey(manifest.RecoveryKeys)
	if err != nil {
		c.zaplogger.Error("could not set up encryption key for sealing the state", zap.Error(err))
		return nil, err
	}
	recoverySecretMap, recoveryData, err := c.recovery.GenerateRecoveryData(manifest.RecoveryKeys)
	if err != nil {
		c.zaplogger.Error("could not generate recovery data", zap.Error(err))
		return nil, err
	}
	c.store.setEncryptionKey(encryptionKey)

	// Parse X.509 admin certificates from manifest
	users, err := generateUsersFromManifest(manifest.Admins)
	if err != nil {
		c.zaplogger.Error("Could not parse specified admin client certificate from supplied manifest", zap.Error(err))
		return nil, err
	}

	c.manifest = manifest
	if err := c.store.putRawManifest("main", rawManifest); err != nil {
		return nil, err
	}
	for key, secret := range secrets {
		if err := c.store.putSecret(key, secret); err != nil {
			return nil, err
		}
	}
	for _, user := range users {
		c.store.putUser(user)
	}

	c.advanceState(stateAcceptingMarbles)
	if err := c.store.sealState(recoveryData); err != nil {
		c.zaplogger.Error("sealState failed", zap.Error(err))
	}

	return recoverySecretMap, nil
}

// GetCertQuote gets the Coordinators certificate and corresponding quote (containing the cert)
//
// Returns the a remote attestation quote of its own certificate alongside this certificate that allows to verify the Coordinator's integrity and authentication for use of the ClientAPI.
func (c *Core) GetCertQuote(ctx context.Context) (string, []byte, error) {
	defer c.mux.Unlock()
	if err := c.requireState(stateAcceptingManifest, stateAcceptingMarbles, stateRecovery); err != nil {
		return "", nil, err
	}

	rootCert, err := c.store.getCertificate("root")
	if err != nil {
		return "", nil, err
	}
	intermediateCert, err := c.store.getCertificate("intermediate")
	if err != nil {
		return "", nil, err
	}

	pemCertRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	if len(pemCertRoot) <= 0 {
		return "", nil, errors.New("pem.EncodeToMemory failed for root certificate")
	}

	// Include intermediate certificate if a manifest has been set
	pemCertIntermediate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateCert.Raw})
	if len(pemCertIntermediate) <= 0 {
		return "", nil, errors.New("pem.EncodeToMemory failed for intermediate certificate")
	}

	strCert := string(pemCertIntermediate) + string(pemCertRoot)
	return strCert, c.quote, nil
}

// GetManifestSignature returns the hash of the manifest
//
// Returns a SHA256 hash of the active manifest.
func (c *Core) GetManifestSignature(ctx context.Context) []byte {
	rawManifest, err := c.store.getRawManifest("main")
	if err != nil {
		return nil
	}
	hash := sha256.Sum256(rawManifest)
	return hash[:]
}

// Recover sets an encryption key (ideally decrypted from the recovery data) and tries to unseal and load a saved state again.
func (c *Core) Recover(ctx context.Context, secret []byte) (int, error) {
	defer c.mux.Unlock()
	if err := c.requireState(stateRecovery); err != nil {
		return -1, err
	}

	remaining, secret, err := c.recovery.RecoverKey(secret)

	if err != nil {
		return remaining, err
	}

	if remaining != 0 {
		return remaining, nil
	}

	if err := c.performRecovery(secret); err != nil {
		return -1, err
	}

	return 0, nil
}

// GetStatus returns status information about the state of the mesh.
func (c *Core) GetStatus(ctx context.Context) (statusCode int, status string, err error) {
	return c.getStatus(ctx)
}

// VerifyAdmin checks if a given client certificate matches the admin certificates specified in the manifest
func (c *Core) VerifyAdmin(ctx context.Context, clientCerts []*x509.Certificate) bool {
	// Check if a supplied client cert matches the supplied ones from the manifest stored in the core
	// NOTE: We do not use the "correct" X.509 verify here since we do not really care about expiration and chain verification here.
	for _, suppliedCert := range clientCerts {
		for user := range c.manifest.Admins {
			userData, _ := c.store.getUser(user)
			if suppliedCert.Equal(userData.certificate) {
				return true
			}
		}
	}

	return false
}

// UpdateManifest allows to update certain package parameters, supplied via a JSON manifest
func (c *Core) UpdateManifest(ctx context.Context, rawUpdateManifest []byte) error {
	defer c.mux.Unlock()

	// Only accept update manifest if we already have a manifest
	if err := c.requireState(stateAcceptingMarbles); err != nil {
		return err
	}

	// Unmarshal & check update manifest
	var updateManifest manifest.Manifest
	if err := json.Unmarshal(rawUpdateManifest, &updateManifest); err != nil {
		return err
	}
	if err := updateManifest.CheckUpdate(ctx, c.manifest.Packages, c.updateManifest.Packages); err != nil {
		return err
	}

	rootCert, err := c.store.getCertificate("root")
	if err != nil {
		return err
	}
	rootPrivK, err := c.store.getPrivK("root")
	if err != nil {
		return err
	}

	// Generate new intermediate CA for Marble gRPC authentication
	intermediateCert, intermediatePrivK, err := generateCert(rootCert.DNSNames, coordinatorIntermediateName, rootCert, rootPrivK)
	if err != nil {
		c.zaplogger.Error("Could not generate a new intermediate CA for Marble authentication.", zap.Error(err))
		return err
	}

	// Gather all shared certificate secrets we need to regenerate
	secretsToRegenerate := make(map[string]manifest.Secret)
	for name, secret := range c.manifest.Secrets {
		if secret.Shared && secret.Type != "symmetric-key" {
			secretsToRegenerate[name] = secret
		}
	}

	// Regenerate shared secrets specified in manifest
	regeneratedSecrets, err := c.generateSecrets(ctx, secretsToRegenerate, uuid.Nil, intermediateCert, intermediatePrivK)
	if err != nil {
		c.zaplogger.Error("Could not generate specified secrets for the given manifest.", zap.Error(err))
		return err
	}

	// Retrieve current recovery data before we seal the state again
	currentRecoveryData, err := c.recovery.GetRecoveryData()
	if err != nil {
		c.zaplogger.Error("Could not retrieve the current recovery data from the recovery module. Cannot reseal the state, the update manifest will not be applied.")
		return err
	}

	c.updateManifest = updateManifest
	if err := c.store.putRawManifest("update", rawUpdateManifest); err != nil {
		return err
	}
	if err := c.store.putCertificate("intermediate", intermediateCert); err != nil {
		return err
	}
	if err := c.store.putPrivK("intermediate", intermediatePrivK); err != nil {
		return err
	}

	// Overwrite regenerated secrets in core
	for name, secret := range regeneratedSecrets {
		if err := c.store.putSecret(name, secret); err != nil {
			return err
		}
	}

	c.zaplogger.Info("An update manifest overriding package settings from the original manifest was set.")
	c.zaplogger.Info("Please restart your Marbles to enforce the update.")

	return c.store.sealState(currentRecoveryData)
}

func (c *Core) performRecovery(encryptionKey []byte) error {
	if err := c.store.setEncryptionKey(encryptionKey); err != nil {
		return err
	}

	// load state
	recoveryData, manifest, updateManifest, err := c.store.loadState()
	if err != nil {
		return err
	}
	if err := c.recovery.SetRecoveryData(recoveryData); err != nil {
		c.zaplogger.Error("Could not retrieve recovery data from state. Recovery will be unavailable", zap.Error(err))
	}

	if manifest != nil {
		c.manifest = *manifest
	}
	if updateManifest != nil {
		c.updateManifest = *updateManifest
	}
	rootCert, err := c.store.getCertificate("root")
	if err != nil {
		return err
	}

	c.quote = c.generateQuote(rootCert.Raw)

	return nil
}
