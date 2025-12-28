/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package clientapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"time"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/crypto"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/multiupdate"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/store"
	dwrapper "github.com/edgelesssys/marblerun/coordinator/store/distributed/wrapper"
	"github.com/edgelesssys/marblerun/coordinator/store/request"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper"
	"github.com/edgelesssys/marblerun/coordinator/user"
	"github.com/edgelesssys/marblerun/util"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ErrNoPendingUpdate is returned when there is no pending update.
var ErrNoPendingUpdate = errors.New("no update in progress")

type secretGetter interface {
	GetIterator(string) (wrapper.Iterator, error)
	PutSecret(string, manifest.Secret) error
	PutPreviousSecret(string, manifest.Secret) error
	GetSecret(string) (manifest.Secret, error)
	DeleteSecret(string) error
	DeletePreviousSecret(string) error
	GetRootSecret() ([]byte, error)
	PutRootSecret([]byte) error
	PutPreviousRootSecret([]byte) error
	PutCertificate(string, *x509.Certificate) error
	GetCertificate(string) (*x509.Certificate, error)
	PutPrivateKey(string, *ecdsa.PrivateKey) error
	GetPrivateKey(string) (*ecdsa.PrivateKey, error)
}

// AcknowledgePendingUpdate adds the user to the list of acknowledgments and returns a list of missing acknowledgments.
func (a *ClientAPI) AcknowledgePendingUpdate(ctx context.Context, rawUpdateManifest []byte, user *user.User) (map[string][]byte, []string, int, error) {
	wrapper, rollback, commit, err := dwrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		return nil, nil, -1, err
	}
	defer rollback()

	pendingUpdate, err := wrapper.GetPendingUpdate()
	if err != nil {
		if errors.Is(err, store.ErrValueUnset) {
			return nil, nil, -1, ErrNoPendingUpdate
		}
		return nil, nil, -1, err
	}

	if err := pendingUpdate.AddAcknowledgment(rawUpdateManifest, user.Name()); err != nil {
		return nil, nil, -1, err
	}

	missingAcks := pendingUpdate.MissingAcknowledgments()
	missingUsers := pendingUpdate.MissingUsers()
	if err := wrapper.PutPendingUpdate(pendingUpdate); err != nil {
		return nil, nil, -1, fmt.Errorf("saving pending update to store: %w", err)
	}
	a.updateLog.Reset()
	a.updateLog.Info(
		"Complete Manifest update acknowledged by user",
		zap.String("user", user.Name()),
		zap.Int("missingAcknowledgments", missingAcks),
		zap.Strings("missingUsers", missingUsers),
		zap.String("manifestFingerprint", pendingUpdate.ManifestFingerprint()),
	)
	if err := wrapper.AppendUpdateLog(a.updateLog.String()); err != nil {
		return nil, nil, -1, fmt.Errorf("saving update log to store: %w", err)
	}
	if err := commit(ctx); err != nil {
		return nil, nil, -1, fmt.Errorf("committing store transaction: %w", err)
	}

	a.log.Info("Received update acknowledgement", zap.String("user", user.Name()), zap.Int("missingAcknowledgments", missingAcks), zap.Strings("missingUsers", missingUsers))
	if missingAcks > 0 {
		return nil, missingUsers, missingAcks, nil
	}

	a.log.Info("All users have acknowledged the update manifest, applying update")
	recoverySecretMap, err := a.updateApply(ctx, pendingUpdate.Manifest())
	if err != nil {
		return nil, nil, 0, err
	}

	return recoverySecretMap, nil, 0, nil
}

// updateApply applies the update manifest.
func (a *ClientAPI) updateApply(ctx context.Context, rawUpdateManifest []byte) (recoverySecretMap map[string][]byte, err error) {
	manifestFingerprint := func() string {
		hash := sha256.Sum256(rawUpdateManifest)
		return hex.EncodeToString(hash[:])
	}()

	// Clean up pending update if something goes wrong
	defer func() {
		if err != nil {
			a.log.Error("Manifest update failed", zap.Error(err))
			// Cancel the pending update
			// Call this asynchronously to not stall the request on failure
			go func() {
				a.log.Info("Trying to cancel pending update...")

				// Two minute timeout for the operation
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()

				// try to delete pending update
				wrapper, rollback, commit, err := dwrapper.WrapTransaction(ctx, a.txHandle)
				if err != nil {
					a.log.Error("Failed to cancel pending update: Failed to initialize store transaction", zap.Error(err))
					return
				}
				defer rollback()

				if err := wrapper.DeletePendingUpdate(); err != nil {
					a.log.Error("Failed to cancel pending update", zap.Error(err))
					return
				}
				a.updateLog.Reset()
				a.updateLog.Info("Complete Manifest update cancelled due to error during apply", zap.String("manifestFingerprint", manifestFingerprint))
				if err := wrapper.AppendUpdateLog(a.updateLog.String()); err != nil {
					a.log.Error("Failed saving update log to store", zap.Error(err)) // don't return on error here, this is just informational
				}
				if err := commit(ctx); err != nil {
					a.log.Error("Failed to cancel pending update: Failed to commit store transaction", zap.Error(err))
					return
				}

				a.log.Info("Pending update cancelled. Fix errors and try again.")
			}()
		}
	}()

	var updateManifest manifest.Manifest
	if err := json.Unmarshal(rawUpdateManifest, &updateManifest); err != nil {
		return nil, fmt.Errorf("unmarshaling update manifest: %w", err)
	}

	wrapper, rollback, commit, err := dwrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		return nil, err
	}
	defer rollback()

	currentManifest, err := wrapper.GetManifest()
	if err != nil {
		return nil, fmt.Errorf("retrieving current manifest: %w", err)
	}

	// Check existing packages against new packages
	if err := updateManifestEntries(
		wrapper, request.Package, updateManifest.Packages,
		wrapper.GetPackage, wrapper.PutPackage, wrapper.DeletePackage,
	); err != nil {
		return nil, fmt.Errorf("updating packages: %w", err)
	}

	// Check existing marbles against new marbles
	if err := updateManifestEntries(
		wrapper, request.Marble, updateManifest.Marbles,
		wrapper.GetMarble, wrapper.PutMarble, wrapper.DeleteMarble,
	); err != nil {
		return nil, fmt.Errorf("updating marbles: %w", err)
	}

	// Check tTLS tags against new tags
	if err := updateManifestEntries(
		wrapper, request.TLS, updateManifest.TLS,
		wrapper.GetTLS, wrapper.PutTLS, wrapper.DeleteTLS,
	); err != nil {
		return nil, fmt.Errorf("updating TLS configs: %w", err)
	}

	// Check infrastructures against new infrastructures
	if err := updateManifestEntries(
		wrapper, request.Infrastructure, updateManifest.Infrastructures,
		wrapper.GetInfrastructure, wrapper.PutInfrastructure, wrapper.DeleteInfrastructure,
	); err != nil {
		return nil, fmt.Errorf("updating infrastructures: %w", err)
	}

	// Update users
	newUsers, err := updateManifest.GenerateUsers()
	if err != nil {
		return nil, fmt.Errorf("generating users from manifest: %w", err)
	}
	userMap := make(map[string]*user.User)
	for _, user := range newUsers {
		userMap[user.Name()] = user
	}
	if err := updateManifestEntries(
		wrapper, request.User, userMap,
		wrapper.GetUser,
		func(_ string, u *user.User) error { return wrapper.PutUser(u) },
		wrapper.DeleteUser,
	); err != nil {
		return nil, fmt.Errorf("updating users: %w", err)
	}

	// Update secrets
	if err := a.updateSecrets(wrapper, updateManifest); err != nil {
		return nil, fmt.Errorf("updating secrets: %w", err)
	}

	// Update the manifest in the store
	if err := wrapper.PutRawManifest(rawUpdateManifest); err != nil {
		return nil, fmt.Errorf("saving updated manifest to store: %w", err)
	}

	rootPrivK, err := wrapper.GetPrivateKey(constants.SKCoordinatorRootKey)
	if err != nil {
		return nil, fmt.Errorf("loading root private key from store: %w", err)
	}
	// sign raw manifest via ECDSA root key
	hash := sha256.Sum256(rawUpdateManifest)
	signature, err := ecdsa.SignASN1(rand.Reader, rootPrivK, hash[:])
	if err != nil {
		a.log.Error("Failed to create the manifest signature", zap.Error(err))
		return nil, fmt.Errorf("signing manifest: %w", err)
	}
	if err := wrapper.PutManifestSignature(signature); err != nil {
		return nil, fmt.Errorf("saving manifest signature to store: %w", err)
	}

	// Remove the pending update, we're done
	if err := wrapper.DeletePendingUpdate(); err != nil {
		return nil, fmt.Errorf("deleting pending update from store: %w", err)
	}

	a.updateLog.Reset()
	a.updateLog.Info("Complete Manifest updated", zap.String("manifestFingerprint", manifestFingerprint))
	if err := wrapper.AppendUpdateLog(a.updateLog.String()); err != nil {
		return nil, fmt.Errorf("saving update log to store: %w", err)
	}

	if recoveryKeysHaveChanged(currentManifest, updateManifest) {
		var recoveryData, encryptionKey []byte
		encryptionKey, recoveryData, recoverySecretMap, err = a.recovery.GenerateEncryptionKey(updateManifest.RecoveryKeys, updateManifest.Config.RecoveryThreshold)
		if err != nil {
			a.log.Error("Could not set up encryption key for sealing the state", zap.Error(err))
			return nil, fmt.Errorf("generating recovery encryption key: %w", err)
		}
		a.txHandle.SetEncryptionKey(encryptionKey, seal.ModeFromString(updateManifest.Config.SealMode))
		a.txHandle.SetRecoveryData(recoveryData)

		defer func() {
			if err != nil {
				a.txHandle.ResetEncryptionKey()
				a.txHandle.ResetRecoveryData()
			}
		}()
	}

	a.hsmEnabler.SetEnabled(updateManifest.HasFeatureEnabled(manifest.FeatureAzureHSMSealing))

	a.log.Info("An updated manifest overriding the original manifest was set.")
	a.log.Info("Please restart your Marbles to enforce the update.")

	if err := commit(ctx); err != nil {
		return nil, fmt.Errorf("committing store transaction: %w", err)
	}

	a.log.Info("UpdateManifest successful")

	return recoverySecretMap, nil
}

// CancelPendingUpdate cancels the pending update.
// This is only possible if the user is allowed to update the manifest, and there is a pending update.
func (a *ClientAPI) CancelPendingUpdate(ctx context.Context, updater *user.User) (err error) {
	defer func() {
		if err != nil {
			a.log.Error("Canceling update failed", zap.Error(err), zap.String("user", updater.Name()))
		}
	}()

	wrapper, rollback, commit, err := dwrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		return err
	}
	defer rollback()

	// Check if the user is allowed to cancel the manifest update
	if !updater.IsGranted(user.NewPermission(user.PermissionUpdateManifest, []string{})) {
		return fmt.Errorf("user %s is not allowed to cancel the manifest update", updater.Name())
	}

	pendingUpdate, err := wrapper.GetPendingUpdate()
	if err != nil {
		if errors.Is(err, store.ErrValueUnset) {
			return ErrNoPendingUpdate
		}
		return err
	}
	if err := wrapper.DeletePendingUpdate(); err != nil {
		return fmt.Errorf("canceling in progress update: %w", err)
	}

	a.updateLog.Reset()
	a.updateLog.Info(
		"Complete Manifest update cancelled by user",
		zap.String("user", updater.Name()),
		zap.String("manifestFingerprint", pendingUpdate.ManifestFingerprint()),
	)
	if err := wrapper.AppendUpdateLog(a.updateLog.String()); err != nil {
		return fmt.Errorf("saving update log to store: %w", err)
	}

	if err := commit(ctx); err != nil {
		return fmt.Errorf("committing store transaction: %w", err)
	}

	a.log.Info("Manifest update canceled", zap.String("user", updater.Name()))
	return nil
}

// GetPendingUpdate returns the pending update.
// This includes the raw manifest, all users that are allowed to update the manifest,
// and which users have already signed off on the update.
func (a *ClientAPI) GetPendingUpdate(ctx context.Context) (*multiupdate.MultiPartyUpdate, error) {
	updateGetter, rollback, _, err := dwrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		return nil, err
	}
	defer rollback()

	pendingUpdate, err := updateGetter.GetPendingUpdate()
	if err != nil {
		if errors.Is(err, store.ErrValueUnset) {
			return nil, ErrNoPendingUpdate
		}
		return nil, err
	}

	return pendingUpdate, nil
}

// updateSecrets updates the secrets in the store according to the new manifest.
//
// This regenerates the Coordinator intermediate certificate and key, and the Marble root certificate.
// Existing shared certificate secrets are also regenerated since they are signed by those CAs.
func (a *ClientAPI) updateSecrets(wrapper secretGetter, mnf manifest.Manifest) error {
	// Remove old secrets that are not in the new manifest
	existingSecrets, err := getExistingEntries(wrapper, request.Secret, wrapper.GetSecret)
	if err != nil {
		a.log.Error("Failed to get existing secrets", zap.Error(err))
		return fmt.Errorf("getting existing secrets: %w", err)
	}
	added, removed, equal := compareKeys(existingSecrets, mnf.Secrets)
	for _, name := range removed {
		if err := wrapper.DeleteSecret(name); err != nil {
			a.log.Error("Failed to delete secret set to be removed in new manifest", zap.Error(err), zap.String("secret", name))
			return fmt.Errorf("deleting secret: %w", err)
		}
		// We only keep secrets as long as they are defined in the manifest
		if err := wrapper.DeletePreviousSecret(name); err != nil {
			a.log.Error("Failed to delete previous secret set to be removed in new manifest", zap.Error(err), zap.String("secret", name))
			return fmt.Errorf("deleting previous secret: %w", err)
		}
	}

	// Delete secrets which definitions have changed
	// They will be regenerated in the next step
	// Secrets that have not changed are kept
	var unchanged []string
	for _, name := range equal {
		if !existingSecrets[name].EqualDefinition(mnf.Secrets[name]) {
			if err := wrapper.DeleteSecret(name); err != nil {
				a.log.Error("Failed to delete secret set to be regenerated in new manifest", zap.Error(err), zap.String("secret", name))
				return fmt.Errorf("deleting secret: %w", err)
			}
			added = append(added, name)
		} else {
			unchanged = append(unchanged, name)
		}
	}

	rootSecret, err := wrapper.GetRootSecret()
	if err != nil {
		a.log.Error("Failed to get root secret", zap.Error(err))
		return fmt.Errorf("loading root secret from store: %w", err)
	}
	rootCert, err := wrapper.GetCertificate(constants.SKCoordinatorRootCert)
	if err != nil {
		a.log.Error("Failed to get root certificate", zap.Error(err))
		return fmt.Errorf("loading root certificate from store: %w", err)
	}
	rootPrivK, err := wrapper.GetPrivateKey(constants.SKCoordinatorRootKey)
	if err != nil {
		a.log.Error("Failed to get root private key", zap.Error(err))
		return fmt.Errorf("loading root private key from store: %w", err)
	}

	// Rotate root secret if configured
	if mnf.Config.RotateRootSecret {
		// Back up root secret
		if err := wrapper.PutPreviousRootSecret(rootSecret); err != nil {
			a.log.Error("Failed backing up root secret", zap.Error(err))
			return fmt.Errorf("backing up root secret: %w", err)
		}

		rootSecret = make([]byte, 32)
		if _, err := rand.Read(rootSecret); err != nil {
			a.log.Error("Could not generate new root secret", zap.Error(err))
			return fmt.Errorf("generating new root secret: %w", err)
		}
		if err := wrapper.PutRootSecret(rootSecret); err != nil {
			a.log.Error("Failed to save new root secret", zap.Error(err))
			return fmt.Errorf("saving new root secret to store: %w", err)
		}
	}

	coordSANs := rootCert.DNSNames
	for _, ip := range rootCert.IPAddresses {
		if !slices.ContainsFunc(util.DefaultCertificateIPAddresses, func(defaultIP net.IP) bool { return ip.Equal(defaultIP) }) {
			coordSANs = append(coordSANs, ip.String())
		}
	}

	// Generate new cross-signed intermediate CA for Marble gRPC authentication
	intermediateCert, intermediatePrivK, err := crypto.GenerateCert(coordSANs, constants.CoordinatorIntermediateName, nil, rootCert, rootPrivK)
	if err != nil {
		a.log.Error("Could not generate a new intermediate CA for Marble authentication.", zap.Error(err))
		return fmt.Errorf("generating new intermediate CA for Marble authentication: %w", err)
	}
	marbleRootCert, _, err := crypto.GenerateCert(coordSANs, constants.CoordinatorIntermediateName, intermediatePrivK, nil, nil)
	if err != nil {
		return fmt.Errorf("generating new Marble root certificate: %w", err)
	}

	// Find out which secrets need to be regenerated
	// User-defined secrets are never generated, but are saved to the store directly
	// All certificates are regenerated, since the intermediate CA changed
	// Symmetric keys are only generated if they are new in this manifest,
	// or if the root secret should be rotated.
	// Otherwise, existing symmetric keys are kept as is
	secretsToGenerate := make(map[string]manifest.Secret)
	for _, name := range added {
		if mnf.Secrets[name].UserDefined {
			if err := wrapper.PutSecret(name, mnf.Secrets[name]); err != nil {
				a.log.Error("Failed to re-save user-defined secret", zap.Error(err), zap.String("secret", name))
				return fmt.Errorf("saving secret %q to store: %w", name, err)
			}

			// Add new user-defined secret also to previous secrets as empty placeholder
			if err := wrapper.PutPreviousSecret(name, mnf.Secrets[name]); err != nil {
				a.log.Error("Failed saving placeholder for secret", zap.Error(err), zap.String("secret", name))
				return fmt.Errorf("creating placeholder for secret %q: %w", name, err)
			}
		} else {
			secretsToGenerate[name] = mnf.Secrets[name]
		}
	}
	for _, name := range unchanged {
		if !mnf.Secrets[name].UserDefined && ((mnf.Secrets[name].Type != manifest.SecretTypeSymmetricKey) || mnf.Config.RotateRootSecret) {
			secretsToGenerate[name] = mnf.Secrets[name]
			// Back up existing (shared) secret before regenerating.
			// This also serves as placeholder for a private secret migrated from older MarbleRun versions.
			secret, err := wrapper.GetSecret(name)
			if err != nil {
				a.log.Error("Failed to get secret", zap.Error(err), zap.String("secret", name))
				return fmt.Errorf("getting secret %q from store: %w", name, err)
			}
			if err := wrapper.PutPreviousSecret(name, secret); err != nil {
				a.log.Error("Failed creating backup of secret", zap.Error(err), zap.String("secret", name))
				return fmt.Errorf("creating backup of secret %q: %w", name, err)
			}
		}
	}

	// Regenerate shared secrets specified in manifest
	secrets, err := a.core.GenerateSecrets(secretsToGenerate, uuid.Nil, "", marbleRootCert, intermediatePrivK, rootSecret)
	if err != nil {
		a.log.Error("Could not generate specified secrets for the given manifest.", zap.Error(err))
		return fmt.Errorf("generating secrets from manifest: %w", err)
	}

	// generate placeholders for private secrets specified in manifest
	privSecrets, err := a.core.GenerateSecrets(secretsToGenerate, uuid.New(), "", marbleRootCert, intermediatePrivK, rootSecret)
	if err != nil {
		a.log.Error("Could not generate specified secrets for the given manifest.", zap.Error(err))
		return fmt.Errorf("generating placeholder secrets from manifest: %w", err)
	}

	maps.Copy(secrets, privSecrets)
	for secretName, secret := range secrets {
		if err := wrapper.PutSecret(secretName, secret); err != nil {
			a.log.Error("Failed to save secret", zap.Error(err), zap.String("secret", secretName))
			return fmt.Errorf("saving secret %q to store: %w", secretName, err)
		}
	}

	// Add newly added secrets to previous secrets as placeholders
	for _, secretName := range added {
		// Skip user-defined secrets, we already added placeholders for them
		if mnf.Secrets[secretName].UserDefined {
			continue
		}
		if err := wrapper.PutPreviousSecret(secretName, secrets[secretName]); err != nil {
			a.log.Error("Failed creating backup of secret", zap.Error(err), zap.String("secret", secretName))
			return fmt.Errorf("creating backup of secret %q: %w", secretName, err)
		}
	}

	// add dummy values for template validation to user defined and symmetric secrets
	for secretName, secret := range mnf.Secrets {
		if secret.UserDefined || secret.Type == manifest.SecretTypeSymmetricKey {
			secret.Cert.Raw = []byte{0x41}
			secret.Private = []byte{0x41}
			secret.Public = []byte{0x41}
			secrets[secretName] = secret
		}
	}

	if err := mnf.TemplateDryRun(secrets); err != nil {
		a.log.Error("Could not validate new manifest template.", zap.Error(err))
		return fmt.Errorf("running manifest template dry run: %w", err)
	}

	if err := wrapper.PutCertificate(constants.SKCoordinatorIntermediateCert, intermediateCert); err != nil {
		a.log.Error("Failed to save new intermediate certificate", zap.Error(err))
		return fmt.Errorf("saving new intermediate certificate to store: %w", err)
	}
	if err := wrapper.PutPrivateKey(constants.SKCoordinatorIntermediateKey, intermediatePrivK); err != nil {
		a.log.Error("Failed to save new intermediate private key", zap.Error(err))
		return fmt.Errorf("saving new intermediate private key to store: %w", err)
	}
	if err := wrapper.PutCertificate(constants.SKMarbleRootCert, marbleRootCert); err != nil {
		a.log.Error("Failed to save new Marble root certificate", zap.Error(err))
		return fmt.Errorf("saving new Marble root certificate to store: %w", err)
	}

	return nil
}

func recoveryKeysHaveChanged(currentManifest, updateManifest manifest.Manifest) bool {
	if len(currentManifest.RecoveryKeys) != len(updateManifest.RecoveryKeys) {
		return true
	}
	// Since a threshold of 0 is equivalent to all keys required, we need to check cases where one config is only different on paper
	if currentManifest.Config.RecoveryThreshold == 0 && (len(updateManifest.RecoveryKeys) == int(updateManifest.Config.RecoveryThreshold)) ||
		updateManifest.Config.RecoveryThreshold == 0 && (len(currentManifest.RecoveryKeys) == int(currentManifest.Config.RecoveryThreshold)) ||
		currentManifest.Config.RecoveryThreshold == updateManifest.Config.RecoveryThreshold {
		return !maps.Equal(currentManifest.RecoveryKeys, updateManifest.RecoveryKeys)
	}
	return true
}
