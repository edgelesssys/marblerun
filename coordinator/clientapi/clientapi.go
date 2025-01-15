/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// package clientapi implements methods for users to interact with the Coordinator.
package clientapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/enclave"
	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/crypto"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/oid"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/store/request"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper"
	"github.com/edgelesssys/marblerun/coordinator/updatelog"
	"github.com/edgelesssys/marblerun/coordinator/user"
	"github.com/edgelesssys/marblerun/util"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type core interface {
	Unlock()
	RequireState(context.Context, ...state.State) error
	AdvanceState(state.State, interface {
		PutState(state.State) error
		GetState() (state.State, error)
	}) error
	GetState(context.Context) (state.State, string, error)
	GenerateSecrets(
		map[string]manifest.Secret, uuid.UUID, string, *x509.Certificate, *ecdsa.PrivateKey, *ecdsa.PrivateKey,
	) (map[string]manifest.Secret, error)
	GetQuote(reportData []byte) ([]byte, error)
	GenerateQuote([]byte) error
}

type transactionHandle interface {
	BeginTransaction(context.Context) (store.Transaction, error)
	SetEncryptionKey([]byte, seal.Mode) error
	SetRecoveryData([]byte)
	LoadState() ([]byte, error)
}

type updateLog interface {
	Info(msg string, fields ...zapcore.Field)
	Reset()
	String() string
}

// QuoteVerifyError is returned if a given quote could not be verified.
type QuoteVerifyError struct {
	err error
}

// Error returns the error message.
func (e QuoteVerifyError) Error() string {
	return fmt.Sprintf("quote verification failed: %s", e.err)
}

// Unwrap returns the wrapped error.
func (e QuoteVerifyError) Unwrap() error {
	return e.err
}

// ClientAPI implements the client API.
type ClientAPI struct {
	core     core
	recovery recovery.Recovery
	txHandle transactionHandle

	updateLog updateLog
	log       *zap.Logger
}

// New returns an initialized instance of the ClientAPI.
func New(txHandle transactionHandle, recovery recovery.Recovery, core core, log *zap.Logger,
) (*ClientAPI, error) {
	updateLog, err := updatelog.New()
	if err != nil {
		return nil, err
	}

	return &ClientAPI{
		core:      core,
		recovery:  recovery,
		txHandle:  txHandle,
		updateLog: updateLog,
		log:       log,
	}, nil
}

// GetCertQuote gets the Coordinators certificate and corresponding quote (containing the cert).
//
// Returns the remote attestation quote of its own certificate alongside this certificate,
// which allows to verify the Coordinator's integrity and authentication for use of the ClientAPI.
func (a *ClientAPI) GetCertQuote(ctx context.Context, nonce []byte) (cert string, certQuote []byte, err error) {
	a.log.Info("GetCertQuote called")
	defer a.core.Unlock()
	if err := a.core.RequireState(ctx, state.AcceptingManifest, state.AcceptingMarbles, state.Recovery); err != nil {
		a.log.Error("GetCertQuote: Coordinator not in correct state", zap.Error(err))
		return "", nil, err
	}
	defer func() {
		if err != nil {
			a.log.Error("GetCertQuote failed", zap.Error(err))
		}
	}()

	txdata, rollback, _, err := wrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		return "", nil, err
	}
	defer rollback()

	rootCert, err := txdata.GetCertificate(constants.SKCoordinatorRootCert)
	if err != nil {
		return "", nil, fmt.Errorf("loading root certificate from store: %w", err)
	}
	if rootCert == nil {
		return "", nil, errors.New("loaded nil root certificate from store")
	}

	intermediateCert, err := txdata.GetCertificate(constants.SKCoordinatorIntermediateCert)
	if err != nil {
		return "", nil, fmt.Errorf("loading intermediate certificate from store: %w", err)
	}
	if intermediateCert == nil {
		return "", nil, errors.New("loaded nil intermediate certificate from store")
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

	// Get existing quote for root cert, or generate a new one over provided nonce
	var reportData []byte
	if len(nonce) > 0 {
		reportData = append(rootCert.Raw, nonce...)
	}
	quote, err := a.core.GetQuote(reportData)
	if err != nil {
		return "", nil, fmt.Errorf("getting quote: %w", err)
	}

	a.log.Info("GetCertQuote successful")
	return string(pemCertIntermediate) + string(pemCertRoot), quote, nil
}

// GetManifestSignature returns the hash of the manifest.
//
// Returns ECDSA signature and byte encoded representation of the active manifest.
func (a *ClientAPI) GetManifestSignature(ctx context.Context) (manifestSignatureRootECDSA, manifest []byte, err error) {
	a.log.Info("GetManifestSignature called")

	txdata, rollback, _, err := wrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		a.log.Error("GetManifestSignature failed: initializing store transaction", zap.Error(err))
		return nil, nil, err
	}
	defer rollback()

	rawManifest, err := txdata.GetRawManifest()
	if err != nil {
		a.log.Error("GetManifestSignature failed: loading manifest from store", zap.Error(err))
		return nil, nil, err
	}
	signature, err := txdata.GetManifestSignature()
	if err != nil {
		a.log.Error("GetManifestSignature failed: loading manifest signature from store", zap.Error(err))
		return nil, nil, err
	}

	a.log.Info("GetManifestSignature successful")
	return signature, rawManifest, nil
}

// GetSecrets allows a user to retrieve secrets from the Coordinator.
func (a *ClientAPI) GetSecrets(ctx context.Context, requestedSecrets []string, client *user.User) (map[string]manifest.Secret, error) {
	a.log.Info("GetSecrets called", zap.Strings("secrets", requestedSecrets), zap.String("user", client.Name()))
	defer a.core.Unlock()
	// we can only return secrets if a manifest has already been set
	if err := a.core.RequireState(ctx, state.AcceptingMarbles); err != nil {
		a.log.Error("GetSecrets: Coordinator not in correct state", zap.Error(err))
		return nil, err
	}

	// verify user is allowed to read the requested secrets
	if !client.IsGranted(user.NewPermission(user.PermissionReadSecret, requestedSecrets)) {
		a.log.Warn(
			"GetSecrets failed: user is not allowed to read one or more secrets",
			zap.Strings("secrets", requestedSecrets), zap.String("user", client.Name()),
		)
		return nil, fmt.Errorf("user %s is not allowed to read one or more secrets of: %v", client.Name(), requestedSecrets)
	}

	txdata, rollback, _, err := wrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		return nil, err
	}
	defer rollback()

	secrets := make(map[string]manifest.Secret)
	for _, requestedSecret := range requestedSecrets {
		returnedSecret, err := txdata.GetSecret(requestedSecret)
		if err != nil {
			a.log.Error("GetSecrets failed: loading secret from store", zap.String("secret", requestedSecret), zap.Error(err))
			return nil, fmt.Errorf("loading secret %s from store: %w", requestedSecret, err)
		}
		secrets[requestedSecret] = returnedSecret
	}

	a.log.Info("GetSecrets successful", zap.Strings("secrets", requestedSecrets), zap.String("user", client.Name()))
	return secrets, nil
}

// GetStatus returns status information about the state of the Coordinator.
func (a *ClientAPI) GetStatus(ctx context.Context) (state.State, string, error) {
	a.log.Info("GetStatus called")
	return a.core.GetState(ctx)
}

// GetUpdateLog returns the update history of the Coordinator.
func (a *ClientAPI) GetUpdateLog(ctx context.Context) ([]string, error) {
	a.log.Info("GetUpdateLog called")
	defer a.core.Unlock()
	if err := a.core.RequireState(ctx, state.AcceptingMarbles); err != nil {
		a.log.Error("GetUpdateLog: Coordinator not in correct state", zap.Error(err))
		return nil, err
	}

	txdata, rollback, _, err := wrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		return nil, err
	}
	defer rollback()

	updateLog, err := txdata.GetUpdateLog()
	if err != nil {
		a.log.Error("GetUpdateLog failed: loading update log from store", zap.Error(err))
		return nil, fmt.Errorf("loading update log from store: %w", err)
	}

	a.log.Info("GetUpdateLog successful")
	return strings.Split(strings.TrimSpace(updateLog), "\n"), nil
}

// Recover sets an encryption key (ideally decrypted from the recovery data) and tries to unseal and load a saved state of the Coordinator.
func (a *ClientAPI) Recover(ctx context.Context, encryptionKey []byte) (keysLeft int, err error) {
	a.log.Info("Recover called")
	defer a.core.Unlock()
	if err := a.core.RequireState(ctx, state.Recovery); err != nil {
		a.log.Error("Recover: Coordinator not in correct state", zap.Error(err))
		return -1, err
	}
	defer func() {
		if err != nil {
			a.log.Error("Recover failed", zap.Error(err))
		}
	}()

	remaining, secret, err := a.recovery.RecoverKey(encryptionKey)
	if err != nil {
		return -1, fmt.Errorf("setting recovery key: %w", err)
	}

	// another key is needed to finish the recovery
	if remaining != 0 {
		a.log.Info("Recover: recovery incomplete, more keys needed", zap.Int("remaining", remaining))
		return remaining, nil
	}

	// all keys are set, we can now load the state
	if err := a.txHandle.SetEncryptionKey(secret, seal.ModeDisabled); err != nil {
		return -1, fmt.Errorf("setting recovery key: %w", err)
	}

	// load state
	recoveryData, err := a.txHandle.LoadState()
	if err != nil {
		return -1, fmt.Errorf("loading state: %w", err)
	}

	a.txHandle.SetRecoveryData(recoveryData)
	if err := a.recovery.SetRecoveryData(recoveryData); err != nil {
		a.log.Error("Could not retrieve recovery data from state. Recovery will be unavailable", zap.Error(err))
	}

	txdata, rollback, _, err := wrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		return -1, err
	}
	defer rollback()

	// set seal mode defined in manifest
	mnf, err := txdata.GetManifest()
	if err != nil {
		return -1, fmt.Errorf("loading manifest from store: %w", err)
	}
	if err := a.txHandle.SetEncryptionKey(secret, seal.ModeFromString(mnf.Config.SealMode)); err != nil {
		return -1, fmt.Errorf("setting recovery key and seal mode: %w", err)
	}

	rootCert, err := txdata.GetCertificate(constants.SKCoordinatorRootCert)
	if err != nil {
		return -1, fmt.Errorf("loading root certificate from store: %w", err)
	}

	if err := a.core.GenerateQuote(rootCert.Raw); err != nil {
		return -1, fmt.Errorf("generating quote failed: %w", err)
	}

	a.log.Info("Recover successful")
	return 0, nil
}

// SetManifest sets the manifest of the Coordinator.
//
// rawManifest is the manifest of type Manifest in JSON format.
// recoverySecretMap is a map of recovery secrets that can be used to recover the Coordinator.
func (a *ClientAPI) SetManifest(ctx context.Context, rawManifest []byte) (recoverySecretMap map[string][]byte, err error) {
	a.log.Info("SetManifest called")
	defer a.core.Unlock()
	if err := a.core.RequireState(ctx, state.AcceptingManifest, state.Recovery); err != nil {
		a.log.Error("SetManifest: Coordinator not in correct state", zap.Error(err))
		return nil, err
	}
	defer func() {
		if err != nil {
			a.log.Error("SetManifest failed", zap.Error(err))
		}
	}()

	var mnf manifest.Manifest
	if err := json.Unmarshal(rawManifest, &mnf); err != nil {
		return nil, fmt.Errorf("unmarshaling manifest: %w", err)
	}
	if err := mnf.Check(a.log); err != nil {
		return nil, fmt.Errorf("checking manifest: %w", err)
	}

	txdata, rollback, commit, err := wrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		return nil, err
	}
	defer rollback()

	marbleRootCert, err := txdata.GetCertificate(constants.SKMarbleRootCert)
	if err != nil {
		return nil, fmt.Errorf("loading root certificate from store: %w", err)
	}
	rootPrivK, err := txdata.GetPrivateKey(constants.SKCoordinatorRootKey)
	if err != nil {
		return nil, fmt.Errorf("loading root private key from store: %w", err)
	}
	intermediatePrivK, err := txdata.GetPrivateKey(constants.SKCoordinatorIntermediateKey)
	if err != nil {
		return nil, fmt.Errorf("loading intermediate private key from store: %w", err)
	}

	// Generate shared secrets specified in manifest
	secrets, err := a.core.GenerateSecrets(mnf.Secrets, uuid.Nil, "", marbleRootCert, intermediatePrivK, rootPrivK)
	if err != nil {
		a.log.Error("Could not generate specified secrets for the given manifest.", zap.Error(err))
		return nil, fmt.Errorf("generating secrets from manifest: %w", err)
	}
	// generate placeholders for private secrets specified in manifest
	privSecrets, err := a.core.GenerateSecrets(mnf.Secrets, uuid.New(), "", marbleRootCert, intermediatePrivK, rootPrivK)
	if err != nil {
		a.log.Error("Could not generate specified secrets for the given manifest.", zap.Error(err))
		return nil, fmt.Errorf("generating placeholder secrets from manifest: %w", err)
	}

	// Set encryption key & generate recovery data
	encryptionKey, err := a.recovery.GenerateEncryptionKey(mnf.RecoveryKeys)
	if err != nil {
		a.log.Error("could not set up encryption key for sealing the state", zap.Error(err))
		return nil, fmt.Errorf("generating recovery encryption key: %w", err)
	}
	recoverySecretMap, recoveryData, err := a.recovery.GenerateRecoveryData(mnf.RecoveryKeys)
	if err != nil {
		a.log.Error("could not generate recovery data", zap.Error(err))
		return nil, fmt.Errorf("generating recovery data: %w", err)
	}
	if err := a.txHandle.SetEncryptionKey(encryptionKey, seal.ModeFromString(mnf.Config.SealMode)); err != nil {
		a.log.Error("could not set encryption key to seal state", zap.Error(err))
		return nil, fmt.Errorf("setting encryption key: %w", err)
	}

	// Parse X.509 user certificates and permissions from manifest
	users, err := mnf.GenerateUsers()
	if err != nil {
		a.log.Error("Could not parse specified user certificate from supplied manifest", zap.Error(err))
		return nil, fmt.Errorf("generating users from manifest: %w", err)
	}

	// sign raw manifest via ECDSA root key
	hash := sha256.Sum256(rawManifest)
	signature, err := ecdsa.SignASN1(rand.Reader, rootPrivK, hash[:])
	if err != nil {
		a.log.Error("Failed to create the manifest signature", zap.Error(err))
		return nil, fmt.Errorf("signing manifest: %w", err)
	}

	for secretName, secret := range privSecrets {
		secrets[secretName] = secret
	}
	for secretName, secret := range secrets {
		if err := txdata.PutSecret(secretName, secret); err != nil {
			return nil, fmt.Errorf("saving secret %q to store: %w", secretName, err)
		}
	}
	for secretName, secret := range mnf.Secrets {
		if secret.UserDefined {
			if err := txdata.PutSecret(secretName, secret); err != nil {
				return nil, fmt.Errorf("saving secret %q to store: %w", secretName, err)
			}

			// dummy values only used for template validation
			secret.Cert.Raw = []byte{0x41}
			secret.Private = []byte{0x41}
			secret.Public = []byte{0x41}
			secrets[secretName] = secret
		}
	}

	if err := mnf.TemplateDryRun(secrets); err != nil {
		return nil, fmt.Errorf("running manifest template dry run: %w", err)
	}

	if err := txdata.PutRawManifest(rawManifest); err != nil {
		return nil, fmt.Errorf("saving manifest to store: %w", err)
	}
	if err := txdata.PutManifestSignature(signature); err != nil {
		return nil, fmt.Errorf("saving manifest signature to store: %w", err)
	}
	for pkgName, pkg := range mnf.Packages {
		if err := txdata.PutPackage(pkgName, pkg); err != nil {
			return nil, fmt.Errorf("saving package %q to store: %w", pkgName, err)
		}
	}
	for infraName, infra := range mnf.Infrastructures {
		if err := txdata.PutInfrastructure(infraName, infra); err != nil {
			return nil, fmt.Errorf("saving infrastructure %q to store: %w", infraName, err)
		}
	}
	for marbleName, marble := range mnf.Marbles {
		if err := txdata.PutMarble(marbleName, marble); err != nil {
			return nil, fmt.Errorf("saving marble %q to store: %w", marbleName, err)
		}
	}
	for tlsCfgName, tlsCfg := range mnf.TLS {
		if err := txdata.PutTLS(tlsCfgName, tlsCfg); err != nil {
			return nil, fmt.Errorf("saving TLS config %q to store: %w", tlsCfgName, err)
		}
	}
	for _, user := range users {
		if err := txdata.PutUser(user); err != nil {
			return nil, fmt.Errorf("saving user %q to store: %w", user.Name(), err)
		}
	}

	a.updateLog.Info("Initial manifest set")
	if err := txdata.PutUpdateLog(a.updateLog.String()); err != nil {
		return nil, fmt.Errorf("saving update log to store: %w", err)
	}

	if err := a.core.AdvanceState(state.AcceptingMarbles, txdata); err != nil {
		return nil, fmt.Errorf("advancing state: %w", err)
	}
	a.txHandle.SetRecoveryData(recoveryData)
	if err := commit(ctx); err != nil {
		a.log.Error("sealing of state failed", zap.Error(err))
		return nil, fmt.Errorf("sealing state: %w", err)
	}

	a.log.Info("SetManifest successful")
	return recoverySecretMap, nil
}

// SetMonotonicCounter sets the new value (if greater) of the counter identified by marbleType, marbleUUID, and name.
func (a *ClientAPI) SetMonotonicCounter(ctx context.Context, marbleType string, marbleUUID uuid.UUID, name string, value uint64) (prevValue uint64, err error) {
	friendlyID := zap.String("id", fmt.Sprintf("%s:%s:%s", marbleType, marbleUUID, name))

	a.log.Info("SetMonotonicCounter called", friendlyID, zap.Uint64("value", value))
	defer a.core.Unlock()
	if err := a.core.RequireState(ctx, state.AcceptingMarbles); err != nil {
		a.log.Error("SetMonotonicCounter: Coordinator not in correct state", zap.Error(err))
		return 0, err
	}
	defer func() {
		if err != nil {
			a.log.Error("SetMonotonicCounter failed", zap.Error(err), friendlyID)
		}
	}()

	counterID := encodeMonotonicCounterID(marbleType, marbleUUID, name)

	txdata, rollback, commit, err := wrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		return 0, err
	}
	defer rollback()

	prevValue, err = txdata.SetMonotonicCounter(counterID, value)
	if err != nil {
		return 0, err
	}

	if err := commit(ctx); err != nil {
		return 0, fmt.Errorf("committing store transaction: %w", err)
	}

	a.log.Info("SetMonotonicCounter successful", friendlyID)
	return prevValue, nil
}

// UpdateManifest allows to update certain package parameters of the original manifest, supplied via a JSON manifest.
func (a *ClientAPI) UpdateManifest(ctx context.Context, rawUpdateManifest []byte, updater *user.User) (err error) {
	a.log.Info("UpdateManifest called")
	defer a.core.Unlock()
	// Only accept update manifest if we already have a manifest
	if err := a.core.RequireState(ctx, state.AcceptingMarbles); err != nil {
		a.log.Error("UpdateManifest: Coordinator not in correct state", zap.Error(err))
		return err
	}
	defer func() {
		if err != nil {
			a.log.Error("UpdateManifest failed", zap.Error(err))
		}
	}()

	// Unmarshal & check update manifest
	var updateManifest manifest.Manifest
	if err := json.Unmarshal(rawUpdateManifest, &updateManifest); err != nil {
		return fmt.Errorf("unmarshaling update manifest: %w", err)
	}

	// verify updater is allowed to commit the update
	var wantedPackages []string
	for pkg := range updateManifest.Packages {
		wantedPackages = append(wantedPackages, pkg)
	}
	if !updater.IsGranted(user.NewPermission(user.PermissionUpdatePackage, wantedPackages)) {
		return fmt.Errorf("user %s is not allowed to update one or more packages of %v", updater.Name(), wantedPackages)
	}

	txdata, rollback, commit, err := wrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		return err
	}
	defer rollback()

	currentPackages := make(map[string]quote.PackageProperties)
	for pkgName := range updateManifest.Packages {
		pkg, err := txdata.GetPackage(pkgName)
		if err != nil {
			return fmt.Errorf("loading current package %q from store: %w", pkgName, err)
		}
		currentPackages[pkgName] = pkg
	}
	if err := updateManifest.CheckUpdate(currentPackages); err != nil {
		return fmt.Errorf("checking update manifest: %w", err)
	}

	// update manifest was valid, increase svn and regenerate secrets
	for pkgName, pkg := range updateManifest.Packages {
		currentPkg := currentPackages[pkgName]
		currentPkg.SecurityVersion = pkg.SecurityVersion
		currentPackages[pkgName] = currentPkg
	}

	rootCert, err := txdata.GetCertificate(constants.SKCoordinatorRootCert)
	if err != nil {
		return fmt.Errorf("loading root certificate from store: %w", err)
	}
	rootPrivK, err := txdata.GetPrivateKey(constants.SKCoordinatorRootKey)
	if err != nil {
		return fmt.Errorf("loading root private key from store: %w", err)
	}

	// Generate new cross-signed intermediate CA for Marble gRPC authentication
	intermediateCert, intermediatePrivK, err := crypto.GenerateCert(rootCert.DNSNames, constants.CoordinatorIntermediateName, nil, rootCert, rootPrivK)
	if err != nil {
		a.log.Error("Could not generate a new intermediate CA for Marble authentication.", zap.Error(err))
		return fmt.Errorf("generating new intermediate CA for Marble authentication: %w", err)
	}
	marbleRootCert, _, err := crypto.GenerateCert(rootCert.DNSNames, constants.CoordinatorIntermediateName, intermediatePrivK, nil, nil)
	if err != nil {
		return fmt.Errorf("generating new Marble root certificate: %w", err)
	}

	// Gather all shared certificate secrets we need to regenerate
	secretsToRegenerate := make(map[string]manifest.Secret)
	secrets, err := txdata.GetSecretMap()
	if err != nil {
		return fmt.Errorf("loading existing shared secrets from store: %w", err)
	}
	for name, secret := range secrets {
		if secret.Shared && secret.Type != manifest.SecretTypeSymmetricKey {
			secretsToRegenerate[name] = secret
		}
	}

	// Regenerate shared secrets specified in manifest
	regeneratedSecrets, err := a.core.GenerateSecrets(secretsToRegenerate, uuid.Nil, "", marbleRootCert, intermediatePrivK, rootPrivK)
	if err != nil {
		a.log.Error("Could not generate specified secrets for the given manifest.", zap.Error(err))
		return fmt.Errorf("regenerating shared secrets for updated manifest: %w", err)
	}

	a.updateLog.Reset()
	for pkgName, pkg := range updateManifest.Packages {
		a.updateLog.Info("SecurityVersion increased", zap.String("user", updater.Name()), zap.String("package", pkgName), zap.Uint("new version", *pkg.SecurityVersion))
	}

	if err := txdata.PutCertificate(constants.SKCoordinatorIntermediateCert, intermediateCert); err != nil {
		return fmt.Errorf("saving new intermediate certificate to store: %w", err)
	}
	if err := txdata.PutPrivateKey(constants.SKCoordinatorIntermediateKey, intermediatePrivK); err != nil {
		return fmt.Errorf("saving new intermediate private key to store: %w", err)
	}
	if err := txdata.PutCertificate(constants.SKMarbleRootCert, marbleRootCert); err != nil {
		return fmt.Errorf("saving new Marble root certificate to store: %w", err)
	}
	if err := txdata.AppendUpdateLog(a.updateLog.String()); err != nil {
		return fmt.Errorf("saving update log to store: %w", err)
	}

	// Overwrite updated packages in core
	for name, pkg := range currentPackages {
		if err := txdata.PutPackage(name, pkg); err != nil {
			return fmt.Errorf("saving updated package to store: %w", err)
		}
	}
	// Overwrite regenerated secrets in core
	for name, secret := range regeneratedSecrets {
		if err := txdata.PutSecret(name, secret); err != nil {
			return fmt.Errorf("saving regenerated secret to store: %w", err)
		}
	}

	a.log.Info("An update manifest overriding package settings from the original manifest was set.")
	a.log.Info("Please restart your Marbles to enforce the update.")

	if err := commit(ctx); err != nil {
		return fmt.Errorf("updating manifest failed: committing store transaction: %w", err)
	}

	a.log.Info("UpdateManifest successful")
	return nil
}

// VerifyMarble checks if a given client certificate is a Marble certificate signed by this Coordinator.
func (a *ClientAPI) VerifyMarble(ctx context.Context, clientCerts []*x509.Certificate) (string, uuid.UUID, error) {
	defer a.core.Unlock()
	if err := a.core.RequireState(ctx, state.AcceptingMarbles); err != nil {
		a.log.Error("VerifyMarble: Coordinator not in correct state", zap.Error(err))
		return "", uuid.UUID{}, err
	}

	txdata, rollback, _, err := wrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		return "", uuid.UUID{}, err
	}
	defer rollback()

	marbleRootCert, err := txdata.GetCertificate(constants.SKMarbleRootCert)
	if err != nil {
		return "", uuid.UUID{}, fmt.Errorf("getting Marble root certificate: %w", err)
	}
	verifyOpts := x509.VerifyOptions{Roots: x509.NewCertPool()}
	verifyOpts.Roots.AddCert(marbleRootCert)

	// Check if a supplied client cert was signed by the Marble root cert and get the type and UUID
	var errs error
	for _, suppliedCert := range clientCerts {
		if _, err := suppliedCert.Verify(verifyOpts); err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		marbleUUID, err := uuid.Parse(suppliedCert.Subject.CommonName)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		for _, ex := range suppliedCert.Extensions {
			if ex.Id.Equal(oid.MarbleType) {
				return string(ex.Value), marbleUUID, nil
			}
		}
		errs = errors.Join(errs, errors.New("MarbleType extension not found in certificate"))
	}

	if errs == nil {
		errs = errors.New("client certificate did not match any Marble")
	}
	return "", uuid.UUID{}, errs
}

// VerifyUser checks if a given client certificate matches the admin certificates specified in the manifest.
func (a *ClientAPI) VerifyUser(ctx context.Context, clientCerts []*x509.Certificate) (*user.User, error) {
	txdata, rollback, _, err := wrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		return nil, err
	}
	defer rollback()

	// Check if a supplied client cert matches the supplied ones from the manifest stored in the core
	// NOTE: We do not use the "correct" X.509 verify here since we do not really care about expiration and chain verification here.
	for _, suppliedCert := range clientCerts {
		userIter, err := txdata.GetIterator(request.User)
		if err != nil {
			return nil, fmt.Errorf("getting user iterator: %w", err)
		}
		for userIter.HasNext() {
			name, err := userIter.GetNext()
			if err != nil {
				return nil, fmt.Errorf("getting next user: %w", err)
			}
			user, err := txdata.GetUser(name)
			if err != nil {
				return nil, fmt.Errorf("getting user %q: %w", name, err)
			}
			if suppliedCert.Equal(user.Certificate()) {
				return user, nil
			}
		}
	}

	return nil, errors.New("client certificate did not match any MarbleRun users")
}

// WriteSecrets allows a user to set certain user-defined secrets for the Coordinator.
func (a *ClientAPI) WriteSecrets(ctx context.Context, userSecrets map[string]manifest.UserSecret, updater *user.User) (err error) {
	a.log.Info("WriteSecrets called", zap.String("user", updater.Name()))
	defer a.core.Unlock()
	// Only accept secrets if we already have a manifest
	if err := a.core.RequireState(ctx, state.AcceptingMarbles); err != nil {
		a.log.Error("WriteSecrets: Coordinator not in correct state", zap.Error(err))
		return err
	}
	defer func() {
		if err != nil {
			a.log.Error("WriteSecrets failed", zap.Error(err), zap.String("user", updater.Name()))
		}
	}()

	txdata, rollback, commit, err := wrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		return err
	}
	defer rollback()

	// validate and parse new secrets
	secretMeta, err := txdata.GetSecretMap()
	if err != nil {
		return fmt.Errorf("loading existing secrets: %w", err)
	}
	newSecrets, err := manifest.ParseUserSecrets(userSecrets, secretMeta)
	if err != nil {
		return fmt.Errorf("parsing new secrets: %w", err)
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
	mnf, err := txdata.GetManifest()
	if err != nil {
		return fmt.Errorf("loading manifest: %w", err)
	}
	// perform the dry run
	if err := mnf.TemplateDryRun(secretMeta); err != nil {
		return fmt.Errorf("running manifest template dry run: %w", err)
	}

	a.updateLog.Reset()
	for secretName, secret := range newSecrets {
		// verify user is allowed to set the secret
		if !updater.IsGranted(user.NewPermission(user.PermissionWriteSecret, []string{secretName})) {
			return fmt.Errorf("user %s is not allowed to update secret: %s", updater.Name(), secretName)
		}
		if err := txdata.PutSecret(secretName, secret); err != nil {
			return fmt.Errorf("saving secret %q to store: %w", secretName, err)
		}
		a.updateLog.Info("Secret set", zap.String("user", updater.Name()), zap.String("secret", secretName), zap.String("type", secret.Type))
	}
	if err := txdata.AppendUpdateLog(a.updateLog.String()); err != nil {
		return fmt.Errorf("saving update log to store: %w", err)
	}

	return commit(ctx)
}

// SignQuote verifies the quote and signs it with the Coordinator's root key.
func (a *ClientAPI) SignQuote(ctx context.Context, quote []byte) (signature []byte, tcbStatus string, err error) {
	a.log.Info("SignQuote called")
	defer func() {
		if err != nil {
			a.log.Error("SignQuote failed", zap.Error(err))
		} else {
			a.log.Info("SignQuote successful")
		}
	}()

	return a.verifyAndSignQuote(ctx, quote, enclave.VerifyRemoteReport)
}

func (a *ClientAPI) verifyAndSignQuote(
	ctx context.Context, quote []byte, verify func([]byte) (attestation.Report, error),
) (signature []byte, tcbStatus string, err error) {
	// Add OE quote header if it is not present
	// e.g. we are dealing with a raw SGX quote generated by Gramine or Occlum
	oeQuote := quote
	if util.IsRawSGXQuote(quote) {
		oeQuote = util.AddOEQuoteHeader(quote)
	}

	// Verify the quote
	report, err := verify(oeQuote)
	if err != nil && !errors.Is(err, attestation.ErrTCBLevelInvalid) {
		return nil, "", &QuoteVerifyError{err}
	}

	// Sign quote and TCB status using Coordinator's root key
	txdata, rollback, _, err := wrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		return nil, "", err
	}
	defer rollback()
	rootKey, err := txdata.GetPrivateKey(constants.SKCoordinatorRootKey)
	if err != nil {
		return nil, "", fmt.Errorf("loading root private key from store: %w", err)
	}

	hash := sha256.Sum256([]byte(base64.StdEncoding.EncodeToString(quote) + report.TCBStatus.String()))
	signature, err = ecdsa.SignASN1(rand.Reader, rootKey, hash[:])
	if err != nil {
		return nil, "", fmt.Errorf("signing quote: %w", err)
	}

	return signature, report.TCBStatus.String(), nil
}

// FeatureEnabled returns true if the given feature is enabled in the manifest.
func (a *ClientAPI) FeatureEnabled(ctx context.Context, feature string) bool {
	txdata, rollback, _, err := wrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		return false
	}
	defer rollback()
	mnf, err := txdata.GetManifest()
	if err != nil {
		return false
	}

	return slices.ContainsFunc(mnf.Config.FeatureGates, func(s string) bool {
		return strings.EqualFold(s, feature)
	})
}

func encodeMonotonicCounterID(marbleType string, marbleUUID uuid.UUID, name string) string {
	// use unambiguous concatenation as counter ID
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("%s:%s:%s", b64([]byte(marbleType)), b64(marbleUUID[:]), b64([]byte(name)))
}
