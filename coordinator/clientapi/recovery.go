/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package clientapi

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/crypto"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/state"
	dwrapper "github.com/edgelesssys/marblerun/coordinator/store/distributed/wrapper"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper"
	"github.com/edgelesssys/marblerun/util"
	"go.uber.org/zap"
)

// RecoveryPublicKey returns the DER encoded ephemeral public key to be used for encrypting recovery secrets.
func (a *ClientAPI) RecoveryPublicKey(ctx context.Context) ([]byte, error) {
	a.log.Info("RecoveryPublicKey called")
	defer a.core.Unlock()
	if err := a.core.RequireState(ctx, state.Recovery); err != nil {
		a.log.Error("RecoveryPublicKey: Coordinator not in correct state", zap.Error(err))
		return nil, err
	}

	pubKey, err := a.recovery.EphemeralPublicKey()
	if err != nil {
		return nil, fmt.Errorf("getting ephemeral public key: %w", err)
	}
	pubKeyDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("marshalling ephemeral public key: %w", err)
	}
	return pubKeyDER, nil
}

// DecryptRecoverySecret decrypts a recovery which was previously encrypted with the key from [*ClientAPI.RecoveryPublicKey].
func (a *ClientAPI) DecryptRecoverySecret(ctx context.Context, encryptedSecret []byte) ([]byte, error) {
	a.log.Info("DecryptRecoverySecret called")
	defer a.core.Unlock()
	if err := a.core.RequireState(ctx, state.Recovery); err != nil {
		a.log.Error("DecryptRecoverySecret: Coordinator not in correct state", zap.Error(err))
		return nil, err
	}

	return a.recovery.DecryptRecoverySecret(encryptedSecret)
}

// Recover sets an encryption key (ideally decrypted from the recovery data) and tries to unseal and load a saved state of the Coordinator.
func (a *ClientAPI) Recover(ctx context.Context, encryptionKey, encryptionKeySignature []byte) (keysLeft int, err error) {
	left, err := a.recover(ctx, encryptionKey, encryptionKeySignature)
	if err != nil || left > 0 {
		return left, err
	}

	// Since a recovery was required, no valid key encryption keys are available.
	// Seal a new key encryption key by committing a transaction and start sharing the key.
	_, rollback, commit, err := dwrapper.WrapTransaction(ctx, a.txHandle)
	if err != nil {
		return 0, err
	}
	defer rollback()
	if err := commit(ctx); err != nil {
		return 0, err
	}

	err = a.keyServer.StartSharing(ctx)
	return 0, err
}

func (a *ClientAPI) recover(ctx context.Context, encryptionKey, encryptionKeySignature []byte) (keysLeft int, retErr error) {
	a.log.Info("Recover called")
	defer a.core.Unlock()
	if err := a.core.RequireState(ctx, state.Recovery); err != nil {
		a.log.Error("Recover: Coordinator not in correct state", zap.Error(err))
		return -1, err
	}
	defer func() {
		if retErr != nil {
			a.log.Error("Recover failed", zap.Error(retErr))
		}
	}()
	if a.recoverySignatureCache == nil {
		a.recoverySignatureCache = make(map[string][]byte)
	}

	remaining, secret, err := a.recovery.RecoverKey(encryptionKey)
	if err != nil {
		return -1, fmt.Errorf("setting recovery key: %w", err)
	}
	a.recoverySignatureCache[string(encryptionKey)] = encryptionKeySignature

	// another key is needed to finish the recovery
	if remaining != 0 {
		a.log.Info("Recover: recovery incomplete, more keys needed", zap.Int("remaining", remaining))
		return remaining, nil
	}

	// reset signature cache on return after this point
	// the recovery module was already cleaned up if no more keys are missing
	defer func() {
		a.recoverySignatureCache = nil
	}()

	// verify the recovery keys before properly loading the state and releasing recovery mode
	sealedStore, err := a.txHandle.BeginReadTransaction(ctx, secret)
	if err != nil {
		return -1, fmt.Errorf("loading sealed state: %w", err)
	}
	readTx := wrapper.New(sealedStore)
	mnf, err := readTx.GetManifest()
	if err != nil {
		return -1, fmt.Errorf("loading manifest from store: %w", err)
	}
	if len(mnf.RecoveryKeys) != len(a.recoverySignatureCache) {
		return -1, fmt.Errorf("recovery keys in manifest do not match the keys used for recovery: expected %d, got %d", len(mnf.RecoveryKeys), len(a.recoverySignatureCache))
	}
	for keyName, keyPEM := range mnf.RecoveryKeys {
		pubKey, err := crypto.ParseRSAPublicKeyFromPEM(keyPEM)
		if err != nil {
			return -1, fmt.Errorf("parsing recovery public key %q: %w", keyName, err)
		}

		found := false
		for key, signature := range a.recoverySignatureCache {
			if err := util.VerifyPKCS1v15(pubKey, []byte(key), signature); err == nil {
				found = true
				delete(a.recoverySignatureCache, key)
				break
			}
		}
		if !found {
			return -1, fmt.Errorf("no matching recovery key found for recovery public key %q", keyName)
		}
	}

	// cache SGX quote over the root certificate
	rootCert, err := readTx.GetCertificate(constants.SKCoordinatorRootCert)
	if err != nil {
		return -1, fmt.Errorf("loading root certificate from store: %w", err)
	}
	if err := a.core.GenerateQuote(rootCert.Raw); err != nil {
		return -1, fmt.Errorf("generating quote failed: %w", err)
	}

	// load state and set seal mode defined in manifest
	a.txHandle.SetEncryptionKey(secret, seal.ModeFromString(mnf.Config.SealMode))
	defer func() {
		if retErr != nil {
			a.txHandle.SetEncryptionKey(nil, seal.ModeDisabled) // reset encryption key in case of failure
		}
	}()
	recoveryData, sealedState, err := a.txHandle.LoadState()
	if err != nil {
		return -1, fmt.Errorf("loading state: %w", err)
	}
	a.txHandle.SetRecoveryData(recoveryData)
	if err := a.recovery.SetRecoveryData(recoveryData); err != nil {
		a.log.Error("Could not retrieve recovery data from state. Recovery will be unavailable", zap.Error(err))
	}
	if err := a.txHandle.SealEncryptionKey(sealedState); err != nil {
		a.log.Error("Could not seal encryption key after recovery. Restart will require another recovery", zap.Error(err))
	}

	a.log.Info("Recover successful")
	return 0, nil
}
