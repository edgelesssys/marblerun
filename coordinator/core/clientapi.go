// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"text/template"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/user"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ClientCore provides the core functionality for the client. It can be used by e.g. a http server
type ClientCore interface {
	SetManifest(ctx context.Context, rawManifest []byte) (recoverySecretMap map[string][]byte, err error)
	GetCertQuote(ctx context.Context) (cert string, certQuote []byte, err error)
	GetManifestSignature(ctx context.Context) (manifestSignature []byte, manifest []byte)
	GetSecrets(ctx context.Context, requestedSecrets []string, requestUser *user.User) (map[string]manifest.Secret, error)
	GetStatus(ctx context.Context) (statusCode int, status string, err error)
	GetUpdateLog(ctx context.Context) (updateLog string, err error)
	Recover(ctx context.Context, encryptionKey []byte) (int, error)
	VerifyUser(ctx context.Context, clientCerts []*x509.Certificate) (*user.User, error)
	UpdateManifest(ctx context.Context, rawUpdateManifest []byte, updater *user.User) error
	WriteSecrets(ctx context.Context, rawSecretManifest []byte, updater *user.User) error
}

// SetManifest sets the manifest, once and for all
//
// rawManifest is the manifest of type Manifest in JSON format.
func (c *Core) SetManifest(ctx context.Context, rawManifest []byte) (map[string][]byte, error) {
	defer c.mux.Unlock()
	if err := c.requireState(stateAcceptingManifest, stateRecovery); err != nil {
		return nil, err
	}

	var mnf manifest.Manifest
	if err := json.Unmarshal(rawManifest, &mnf); err != nil {
		return nil, err
	}
	if err := mnf.Check(ctx, c.zaplogger); err != nil {
		return nil, err
	}

	marbleRootCert, err := c.data.getCertificate(sKMarbleRootCert)
	if err != nil {
		return nil, err
	}
	intermediatePrivK, err := c.data.getPrivK(sKCoordinatorIntermediateKey)
	if err != nil {
		return nil, err
	}

	// Generate shared secrets specified in manifest
	secrets, err := c.generateSecrets(ctx, mnf.Secrets, uuid.Nil, marbleRootCert, intermediatePrivK)
	if err != nil {
		c.zaplogger.Error("Could not generate specified secrets for the given manifest.", zap.Error(err))
		return nil, err
	}
	// generate placeholders for private secrets specified in manifest
	privSecrets, err := c.generateSecrets(ctx, mnf.Secrets, uuid.New(), marbleRootCert, intermediatePrivK)
	if err != nil {
		c.zaplogger.Error("Could not generate specified secrets for the given manifest.", zap.Error(err))
		return nil, err
	}

	// Set encryption key & generate recovery data
	encryptionKey, err := c.recovery.GenerateEncryptionKey(mnf.RecoveryKeys)
	if err != nil {
		c.zaplogger.Error("could not set up encryption key for sealing the state", zap.Error(err))
		return nil, err
	}
	recoverySecretMap, recoveryData, err := c.recovery.GenerateRecoveryData(mnf.RecoveryKeys)
	if err != nil {
		c.zaplogger.Error("could not generate recovery data", zap.Error(err))
		return nil, err
	}
	c.sealer.SetEncryptionKey(encryptionKey)

	// Parse X.509 user certificates and permissions from manifest
	users, err := generateUsersFromManifest(mnf.Users, mnf.Roles)
	if err != nil {
		c.zaplogger.Error("Could not parse specified user certificate from supplied manifest", zap.Error(err))
		return nil, err
	}

	tx, err := c.store.BeginTransaction()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	txdata := storeWrapper{tx}

	for k, v := range privSecrets {
		secrets[k] = v
	}
	for k, v := range secrets {
		if err := txdata.putSecret(k, v); err != nil {
			return nil, err
		}
	}
	for k, v := range mnf.Secrets {
		if v.UserDefined {
			if err := txdata.putSecret(k, v); err != nil {
				return nil, err
			}

			// dummy values only used for template validation
			v.Cert.Raw = []byte{0x41}
			v.Private = []byte{0x41}
			v.Public = []byte{0x41}
			secrets[k] = v
		}
	}

	if err := templateDryRun(mnf, secrets); err != nil {
		return nil, err
	}

	if err := txdata.putRawManifest(rawManifest); err != nil {
		return nil, err
	}
	for k, v := range mnf.Packages {
		if err := txdata.putPackage(k, v); err != nil {
			return nil, err
		}
	}
	for k, v := range mnf.Infrastructures {
		if err := txdata.putInfrastructure(k, v); err != nil {
			return nil, err
		}
	}
	for k, v := range mnf.Marbles {
		if err := txdata.putMarble(k, v); err != nil {
			return nil, err
		}
	}
	for k, v := range mnf.TLS {
		if err := txdata.putTLS(k, v); err != nil {
			return nil, err
		}
	}
	for _, user := range users {
		if err := txdata.putUser(user); err != nil {
			return nil, err
		}
	}

	c.updateLogger.Info("initial manifest set")
	if err := txdata.putUpdateLog(c.updateLogger.String()); err != nil {
		return nil, err
	}

	c.advanceState(stateAcceptingMarbles, tx)
	if store, ok := c.store.(*store.StdStore); ok {
		store.SetRecoveryData(recoveryData)
	}
	if err := tx.Commit(); err != nil {
		c.zaplogger.Error("sealing of state failed", zap.Error(err))
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

	rootCert, err := c.data.getCertificate(sKCoordinatorRootCert)
	if err != nil {
		return "", nil, err
	}
	intermediateCert, err := c.data.getCertificate(skCoordinatorIntermediateCert)
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
func (c *Core) GetManifestSignature(ctx context.Context) ([]byte, []byte) {
	rawManifest, err := c.data.getRawManifest()
	if err != nil {
		return nil, nil
	}
	hash := sha256.Sum256(rawManifest)
	return hash[:], rawManifest
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

// GetUpdateLog returns the update history of the coordinator
func (c *Core) GetUpdateLog(ctx context.Context) (string, error) {
	defer c.mux.Unlock()
	if err := c.requireState(stateAcceptingMarbles); err != nil {
		return "", err
	}
	return c.data.getUpdateLog()
}

// VerifyUser checks if a given client certificate matches the admin certificates specified in the manifest
func (c *Core) VerifyUser(ctx context.Context, clientCerts []*x509.Certificate) (*user.User, error) {
	userIter, err := c.data.getIterator(requestUser)
	if err != nil {
		return nil, err
	}
	// Check if a supplied client cert matches the supplied ones from the manifest stored in the core
	// NOTE: We do not use the "correct" X.509 verify here since we do not really care about expiration and chain verification here.
	for _, suppliedCert := range clientCerts {
		for userIter.HasNext() {
			name, err := userIter.GetNext()
			if err != nil {
				return nil, err
			}
			user, err := c.data.getUser(name)
			if err != nil {
				return nil, err
			}
			if suppliedCert.Equal(user.Certificate()) {
				return user, nil
			}
		}
	}

	return nil, errors.New("client certificate did not match any MarbleRun users")
}

// UpdateManifest allows to update certain package parameters, supplied via a JSON manifest
func (c *Core) UpdateManifest(ctx context.Context, rawUpdateManifest []byte, updater *user.User) error {
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

	// verify updater is allowed to commit the update
	var wantedPackages []string
	for pkg := range updateManifest.Packages {
		wantedPackages = append(wantedPackages, pkg)
	}
	if !updater.IsGranted(user.NewPermission(user.PermissionUpdatePackage, wantedPackages)) {
		return fmt.Errorf("user %s is not allowed to update one or more packages of %v", updater.Name(), wantedPackages)
	}

	currentPackages := make(map[string]quote.PackageProperties)
	for pkgName := range updateManifest.Packages {
		pkg, err := c.data.getPackage(pkgName)
		if err != nil {
			return err
		}
		currentPackages[pkgName] = pkg
	}
	if err := updateManifest.CheckUpdate(ctx, currentPackages); err != nil {
		return err
	}

	// update manifest was valid, increase svn and regenerate secrets
	for pkgName, pkg := range updateManifest.Packages {
		*currentPackages[pkgName].SecurityVersion = *pkg.SecurityVersion
	}

	rootCert, err := c.data.getCertificate(sKCoordinatorRootCert)
	if err != nil {
		return err
	}
	rootPrivK, err := c.data.getPrivK(sKCoordinatorRootKey)
	if err != nil {
		return err
	}

	// Generate new cross-signed intermediate CA for Marble gRPC authentication
	intermediateCert, intermediatePrivK, err := generateCert(rootCert.DNSNames, coordinatorIntermediateName, nil, rootCert, rootPrivK)
	if err != nil {
		c.zaplogger.Error("Could not generate a new intermediate CA for Marble authentication.", zap.Error(err))
		return err
	}
	marbleRootCert, _, err := generateCert(rootCert.DNSNames, coordinatorIntermediateName, intermediatePrivK, nil, nil)
	if err != nil {
		return err
	}

	// Gather all shared certificate secrets we need to regenerate
	secretsToRegenerate := make(map[string]manifest.Secret)
	secrets, err := c.data.getSecretMap()
	if err != nil {
		return err
	}
	for name, secret := range secrets {
		if secret.Shared && secret.Type != "symmetric-key" {
			secretsToRegenerate[name] = secret
		}
	}

	// Regenerate shared secrets specified in manifest
	regeneratedSecrets, err := c.generateSecrets(ctx, secretsToRegenerate, uuid.Nil, marbleRootCert, intermediatePrivK)
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

	c.updateLogger.Reset()
	for pkgName, pkg := range updateManifest.Packages {
		c.updateLogger.Info("SecurityVersion increased", zap.String("user", updater.Name()), zap.String("package", pkgName), zap.Uint("new version", *pkg.SecurityVersion))
	}

	tx, err := c.store.BeginTransaction()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	txdata := storeWrapper{tx}

	if err := txdata.putCertificate(skCoordinatorIntermediateCert, intermediateCert); err != nil {
		return err
	}
	if err := txdata.putCertificate(sKMarbleRootCert, marbleRootCert); err != nil {
		return err
	}
	if err := txdata.putPrivK(sKCoordinatorIntermediateKey, intermediatePrivK); err != nil {
		return err
	}
	if err := txdata.appendUpdateLog(c.updateLogger.String()); err != nil {
		return err
	}

	// Overwrite updated packages in core
	for name, pkg := range currentPackages {
		if err := txdata.putPackage(name, pkg); err != nil {
			return err
		}
	}
	// Overwrite regenerated secrets in core
	for name, secret := range regeneratedSecrets {
		if err := txdata.putSecret(name, secret); err != nil {
			return err
		}
	}

	c.zaplogger.Info("An update manifest overriding package settings from the original manifest was set.")
	c.zaplogger.Info("Please restart your Marbles to enforce the update.")

	if store, ok := c.store.(*store.StdStore); ok {
		store.SetRecoveryData(currentRecoveryData)
	}
	return tx.Commit()
}

// GetSecrets allows a user to read out secrets from the core
func (c *Core) GetSecrets(ctx context.Context, requestedSecrets []string, client *user.User) (map[string]manifest.Secret, error) {
	defer c.mux.Unlock()

	// we can only return secrets if a manifest has already been set
	if err := c.requireState(stateAcceptingMarbles); err != nil {
		return nil, err
	}

	// verify user is allowed to read the requested secrets
	if !client.IsGranted(user.NewPermission(user.PermissionReadSecret, requestedSecrets)) {
		return nil, fmt.Errorf("user %s is not allowed to read one or more secrets of: %v", client.Name(), requestedSecrets)
	}

	secrets := make(map[string]manifest.Secret)
	for _, requestedSecret := range requestedSecrets {
		returnedSecret, err := c.data.getSecret(requestedSecret)
		if err != nil {
			return nil, err
		}
		secrets[requestedSecret] = returnedSecret
	}

	return secrets, nil
}

// WriteSecrets allows a user to set certain user-defined secrets
func (c *Core) WriteSecrets(ctx context.Context, rawSecretManifest []byte, updater *user.User) error {
	defer c.mux.Unlock()

	// Only accept secrets if we already have a manifest
	if err := c.requireState(stateAcceptingMarbles); err != nil {
		return err
	}

	// Unmarshal & check secret manifest
	var secretManifest map[string]manifest.UserSecret
	if err := json.Unmarshal(rawSecretManifest, &secretManifest); err != nil {
		return err
	}

	// validate and parse new secrets
	secretMeta, err := c.data.getSecretMap()
	if err != nil {
		return err
	}
	newSecrets, err := manifest.ParseUserSecrets(ctx, secretManifest, secretMeta)
	if err != nil {
		return err
	}

	// perform a dry run to check if the new secrets can be parsed as env vars or files
	//
	// set dummy values for user-defined secrets, only used for template validation, we do not care if any of these were set before
	for k, v := range secretMeta {
		if v.UserDefined {
			v.Cert.Raw = []byte{0x41}
			v.Private = []byte{0x41}
			v.Public = []byte{0x41}
			secretMeta[k] = v
		}
	}
	// merge new secrets with existing secrets
	for k, v := range newSecrets {
		secretMeta[k] = v
	}
	mnf, err := c.data.getManifest()
	if err != nil {
		return err
	}
	// perform the dry run
	if err := templateDryRun(mnf, secretMeta); err != nil {
		return err
	}

	tx, err := c.store.BeginTransaction()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	txdata := storeWrapper{tx}

	c.updateLogger.Reset()
	for secretName, secret := range newSecrets {
		// verify user is allowed to set the secret
		if !updater.IsGranted(user.NewPermission(user.PermissionWriteSecret, []string{secretName})) {
			return fmt.Errorf("user %s is not allowed to update secret: %s", updater.Name(), secretName)
		}
		if err := txdata.putSecret(secretName, secret); err != nil {
			return err
		}
		c.updateLogger.Info("secret set", zap.String("user", updater.Name()), zap.String("secret", secretName), zap.String("type", secret.Type))
	}
	if err := txdata.appendUpdateLog(c.updateLogger.String()); err != nil {
		return err
	}

	return tx.Commit()
}

func (c *Core) performRecovery(encryptionKey []byte) error {
	if err := c.sealer.SetEncryptionKey(encryptionKey); err != nil {
		return err
	}

	// load state
	store := store.NewStdStore(c.sealer)
	recoveryData, err := store.LoadState()
	if err != nil {
		return err
	}
	c.store = store
	c.data = storeWrapper{store}
	if err := c.recovery.SetRecoveryData(recoveryData); err != nil {
		c.zaplogger.Error("Could not retrieve recovery data from state. Recovery will be unavailable", zap.Error(err))
	}

	rootCert, err := c.data.getCertificate(sKCoordinatorRootCert)
	if err != nil {
		return err
	}
	c.quote = c.generateQuote(rootCert.Raw)

	return nil
}

// templateDryRun performs a dry run for Files and Env declarations in a manifest
func templateDryRun(mnf manifest.Manifest, secrets map[string]manifest.Secret) error {
	templateSecrets := secretsWrapper{
		Secrets: secrets,
		MarbleRun: reservedSecrets{
			RootCA: manifest.Secret{
				Cert: manifest.Certificate{Raw: []byte{0x41}},
			},
			MarbleCert: manifest.Secret{
				Cert:    manifest.Certificate{Raw: []byte{0x41}},
				Public:  []byte{0x41},
				Private: []byte{0x41},
			},
		},
	}
	// make sure templates in file/env declarations can actually be executed
	for mN, m := range mnf.Marbles {
		for fN, file := range m.Parameters.Files {
			if !file.NoTemplates {
				if err := checkFileTemplates(file.Data, manifest.ManifestFileTemplateFuncMap, templateSecrets); err != nil {
					return fmt.Errorf("Marble %s: file %s: %v", mN, fN, err)
				}
			}
		}
		for eN, env := range m.Parameters.Env {
			// make sure environment variables dont contain NULL bytes, we perform another check at runtime to catch NULL bytes in secrets
			if strings.Contains(env.Data, string([]byte{0x00})) {
				return fmt.Errorf("Marble %s: env variable: %s: content contains null bytes", mN, eN)
			}
			if !env.NoTemplates {
				if err := checkFileTemplates(env.Data, manifest.ManifestEnvTemplateFuncMap, templateSecrets); err != nil {
					return fmt.Errorf("Marble %s: env variable %s: %v", mN, eN, err)
				}
			}
		}
	}

	return nil
}

func checkFileTemplates(data string, tplFunc template.FuncMap, secrets secretsWrapper) error {
	tpl, err := template.New("data").Funcs(tplFunc).Parse(data)
	if err != nil {
		return err
	}
	return tpl.Execute(&bytes.Buffer{}, secrets)
}
