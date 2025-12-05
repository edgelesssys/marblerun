/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package recovery

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/edgelesssys/marblerun/3rdparty/hashicorp/shamir"
	ccrypto "github.com/edgelesssys/marblerun/coordinator/crypto"
	"github.com/edgelesssys/marblerun/util"
	"go.uber.org/zap"
)

// MultiPartyRecovery is a recoverer with support for single-party recovery and multi-party recovery.
type MultiPartyRecovery struct {
	encryptionKey   []byte
	secretMap       map[string][]byte
	SecretHashMap   map[string]bool
	correctSecrets  int
	combinedKey     []byte
	providedSecrets [][]byte
	store           store

	// ephemeralSecretKey can be used by clients to encrypt their recovery secrets before sending them to the Coordinator.
	ephemeralSecretKey *rsa.PrivateKey

	log *zap.Logger
}

// New generates a multi-party recoverer which the core can use to call recovery functions.
func New(store store, log *zap.Logger) *MultiPartyRecovery {
	return &MultiPartyRecovery{store: store, log: log}
}

// GenerateEncryptionKey generates an encryption key according to the implicitly defined recovery mode.
func (r *MultiPartyRecovery) GenerateEncryptionKey(recoveryKeys map[string]string, recoveryThreshold uint) ([]byte, error) {
	var err error

	switch {
	// If only one recovery keys is provided, generate a single random key for single-party recovery
	case len(recoveryKeys) <= 1:
		r.log.Debug("Single recovery key received, generating single-party encryption key")
		r.encryptionKey, err = generateRandomKey()
		r.secretMap, r.SecretHashMap = nil, nil // wipe potentially previous multi-party recovery data
	// If multiple keys are provided, and the recovery threshold equals the amount of provided keys (or is 0, i.e. the default),
	// generate multiple keys and XOR them together for multi-party recovery
	case recoveryThreshold == uint(len(recoveryKeys)) || recoveryThreshold == 0:
		r.log.Debug("Multiple recovery keys received, generating multi-party encryption key", zap.Int("recoveryKeys", len(recoveryKeys)))
		r.encryptionKey, r.secretMap, r.SecretHashMap, err = generateMultiPartyRecoveryKey(recoveryKeys, r.log)
	// Multiple keys with a threshold were provided: use Shamir's secrets sharing to generate the encryption key
	case int(recoveryThreshold) < len(recoveryKeys):
		r.log.Debug("Multiple recovery keys with threshold received, using Shamir's secrets sharing to generate encryption key", zap.Int("recoveryKeys", len(recoveryKeys)), zap.Uint("recoveryThreshold", recoveryThreshold))
		r.encryptionKey, r.secretMap, r.SecretHashMap, err = generateShamirRecoveryKey(recoveryKeys, recoveryThreshold, r.log)
	default:
		err = fmt.Errorf("invalid configuration to create recovery key: %d recovery keys with recovery threshold of %d", len(recoveryKeys), recoveryThreshold)
	}

	if err != nil {
		return nil, err
	}
	return r.encryptionKey, nil
}

// GenerateRecoveryData generates the recovery data which is returned to the user.
func (r *MultiPartyRecovery) GenerateRecoveryData(recoveryKeys map[string]string) (map[string][]byte, []byte, error) {
	r.log.Debug("Generating recovery data")
	// For single party recovery, just create a new map here and return one single key
	if len(r.secretMap) == 0 {
		r.log.Debug("Coordinator is in single-party recovery mode, creating secret map")
		r.secretMap = make(map[string][]byte, 1)
		for index, value := range recoveryKeys {
			// Parse RSA Public Key
			recoveryk, err := ccrypto.ParseRSAPublicKeyFromPEM(value)
			if err != nil {
				return nil, nil, err
			}

			// Encrypt encryption key with user-specified RSA public key
			r.secretMap[index], err = util.EncryptOAEP(recoveryk, r.encryptionKey)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	// prepare recovery info data
	marshalledSecretHashMap, err := json.Marshal(r.SecretHashMap)
	if err != nil {
		return nil, nil, err
	}
	// Return freshly generated map for single-party recovery, or return already existing one for multi-part recovery
	r.log.Debug("Recovery data generated", zap.ByteString("recoveryData", marshalledSecretHashMap))
	return r.secretMap, marshalledSecretHashMap, nil
}

// RecoverKey is called by the client api, decides whether to perform single-party recovery or multi-party recovery and returns the (hopefully correct) key.
func (r *MultiPartyRecovery) RecoverKey(secret []byte) (int, []byte, error) {
	// Single-Party Recovery or no recovery data available
	if r.SecretHashMap == nil {
		return r.recoverKey(secret)
	}

	// Multi-Party Recovery using shamir's secret sharing
	if len(secret) == RecoveryKeySize+1 {
		return r.shamirRecover(secret)
	}
	// Regular Multi-Party Recovery
	return r.multiPartyRecover(secret)
}

// SetRecoveryData sets the recovery hash map retrieved from the sealer on (failed) decryption.
func (r *MultiPartyRecovery) SetRecoveryData(data []byte) error {
	var secretHashMap map[string]bool
	if err := json.Unmarshal(data, &secretHashMap); err != nil {
		return err
	}

	r.SecretHashMap = secretHashMap
	return nil
}

// EphemeralPublicKey returns the ephemeral public key to encrypt recovery secrets.
func (r *MultiPartyRecovery) EphemeralPublicKey() (crypto.PublicKey, error) {
	if r.ephemeralSecretKey == nil {
		ephemeralKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, err
		}
		r.ephemeralSecretKey = ephemeralKey
	}

	return &r.ephemeralSecretKey.PublicKey, nil
}

// DecryptRecoverySecret decrypts an encrypted recovery secret using the ephemeral secret key.
func (r *MultiPartyRecovery) DecryptRecoverySecret(encryptedSecret []byte) ([]byte, error) {
	if r.ephemeralSecretKey == nil {
		return nil, errors.New("ephemeral secret key not set")
	}

	return rsa.DecryptOAEP(sha256.New(), nil, r.ephemeralSecretKey, encryptedSecret, nil)
}

func (r *MultiPartyRecovery) multiPartyRecover(secret []byte) (int, []byte, error) {
	uploadedSecretHash := Hash(secret)
	secretsRemaining := len(r.SecretHashMap) - r.correctSecrets
	r.log.Debug("Checking recovery secret", zap.String("secretHash", uploadedSecretHash), zap.Int("secretsRemaining", secretsRemaining))

	if err := r.validateSecretLength(secret); err != nil {
		return secretsRemaining, nil, err
	}

	if r.combinedKey == nil {
		r.combinedKey = make([]byte, len(secret))
	}

	// If we haven't reached max count yet, let users upload another secret
	if r.correctSecrets < len(r.SecretHashMap) {
		r.log.Debug("Checking if supplied secret is valid and unused")
		if value, ok := r.SecretHashMap[uploadedSecretHash]; value && ok {
			r.log.Debug("Secret is valid and unused, updating combined recovery key")
			newCombinedKey, err := util.XORBytes(r.combinedKey, secret)
			if err != nil {
				r.log.Error("Failed to update combined recovery key", zap.Error(err))
				return secretsRemaining, nil, err
			}

			r.correctSecrets++
			secretsRemaining = len(r.SecretHashMap) - r.correctSecrets
			r.SecretHashMap[uploadedSecretHash] = false

			r.combinedKey = newCombinedKey
		} else {
			return secretsRemaining, nil, errors.New("uploaded an invalid or already used secret")
		}
	}

	// If we reached the right amount of secrets, try to decrypt the encryption key and use the single-party recovery function to recover.
	if r.correctSecrets == len(r.SecretHashMap) {
		r.log.Debug("All secrets uploaded, cleaning up")
		defer r.cleanup()
		return secretsRemaining, r.combinedKey, nil
	}

	// If we haven't reached the maximum amount of secrets yet, print the remaining secrets to upload
	r.log.Debug("Recovery secret processed successfully", zap.Int("secretsRemaining", secretsRemaining))
	return secretsRemaining, nil, nil
}

// cleanup resets recovery state after successful multi-party recovery.
func (r *MultiPartyRecovery) cleanup() {
	r.correctSecrets = 0
	r.combinedKey = nil
	r.ephemeralSecretKey = nil
	r.providedSecrets = nil

	for index := range r.SecretHashMap {
		r.SecretHashMap[index] = true
	}
}

func (r *MultiPartyRecovery) recoverKey(secret []byte) (int, []byte, error) {
	if err := r.validateSecretLength(secret); err != nil {
		return -1, nil, err
	}

	ciphertext, err := r.store.GetCiphertext()
	if err != nil {
		return -1, nil, fmt.Errorf("getting ciphertext: %w", err)
	}
	if r.store.TestKey(secret, ciphertext) {
		r.log.Debug("Single-party recovery: correct secret provided")
		return 0, secret, nil
	}

	r.providedSecrets = append(r.providedSecrets, secret)
	lenSecrets := len(r.providedSecrets)

	if lenSecrets == 1 {
		r.log.Warn("Recovery data not available and provided secret couldn't decrypt the ciphertext. Assuming multi-party recovery. Please provide more secrets.")
		return 1, nil, nil
	}

	// always try all combinations
	for i := 1; i < (1 << lenSecrets); i++ {
		combinedKey := make([]byte, len(secret))
		secretHashMap := map[string]bool{}
		for j := range lenSecrets {
			// check if the j-th bit in i is set
			if i&(1<<j) != 0 {
				secret := r.providedSecrets[j]
				combinedKey, err = util.XORBytes(combinedKey, secret)
				if err != nil {
					return -1, nil, err
				}
				secretHashMap[Hash(secret)] = true

				if r.store.TestKey(combinedKey, ciphertext) {
					r.providedSecrets = nil
					r.log.Debug("Multi-party recovery: found valid combination of secrets")

					// recreate recovery data; log errors if any, but continue recovery in any case
					if marshalledSecretHashMap, err := json.Marshal(secretHashMap); err != nil {
						r.log.Error("Failed to marshal recreated recovery data", zap.Error(err))
					} else {
						r.log.Debug("Recovery data recreated", zap.ByteString("recoveryData", marshalledSecretHashMap))
						if err := r.store.PersistRecoveryData(marshalledSecretHashMap); err != nil {
							r.log.Error("Failed to persist recreated recovery data", zap.Error(err))
						}
					}

					return 0, combinedKey, nil
				}
			}
		}
	}

	r.log.Warn("Provided secrets so far couldn't decrypt the ciphertext. Please provide more secrets.", zap.Int("secretsProvided", lenSecrets))

	return 1, nil, nil
}

func (r *MultiPartyRecovery) shamirRecover(secret []byte) (int, []byte, error) {
	uploadedSecretHash := Hash(secret)
	secretsRemaining := len(r.SecretHashMap) - r.correctSecrets
	r.log.Debug("Checking recovery secret", zap.String("secretHash", uploadedSecretHash), zap.Int("secretsRemaining", secretsRemaining))

	if err := r.validateSecretLengthShamir(secret); err != nil {
		return -1, nil, err
	}

	if r.SecretHashMap != nil {
		r.log.Debug("Checking if supplied secret is valid and unused")
		if value, ok := r.SecretHashMap[uploadedSecretHash]; value && ok {
			r.log.Debug("Secret is valid and unused, adding to provided secrets")
			r.providedSecrets = append(r.providedSecrets, secret)
			r.correctSecrets++
			secretsRemaining = len(r.SecretHashMap) - r.correctSecrets
			r.SecretHashMap[uploadedSecretHash] = false
		} else {
			return secretsRemaining, nil, errors.New("uploaded an invalid or already used secret")
		}
	} else {
		r.log.Warn("No recovery data available, assuming all provided secrets are valid")
		// Check if secret was already provided
		for _, providedSecret := range r.providedSecrets {
			if bytes.Equal(providedSecret, secret) {
				return secretsRemaining, nil, errors.New("uploaded an already used secret")
			}
		}
		r.log.Debug("Adding secret to provided secrets")
		r.providedSecrets = append(r.providedSecrets, secret)
		r.correctSecrets++
	}

	// If this was the first secret uploaded, just return
	if r.correctSecrets < 2 {
		r.log.Debug("Shamir recovery secret processed successfully", zap.Int("secretsRemaining", secretsRemaining))
		return secretsRemaining, nil, nil
	}

	// Try to recover the key if enough secrets have been provided
	recoveredKey, err := shamir.Combine(r.providedSecrets)
	if err != nil {
		r.log.Error("Failed to combine provided Shamir secrets", zap.Error(err))
		return secretsRemaining, nil, err
	}

	// Check if the recovered key is correct
	ciphertext, err := r.store.GetCiphertext()
	if err != nil {
		return -1, nil, fmt.Errorf("getting ciphertext: %w", err)
	}

	if r.store.TestKey(recoveredKey, ciphertext) {
		r.log.Debug("Shamir multi-party recovery: correct key recovered, cleaning up")
		defer r.cleanup()

		if r.SecretHashMap == nil {
			secretHashMap := map[string]bool{}
			for _, secret := range r.providedSecrets {
				secretHashMap[Hash(secret)] = true
			}
			if marshalledSecretHashMap, err := json.Marshal(secretHashMap); err != nil {
				r.log.Error("Failed to marshal recreated recovery data", zap.Error(err))
			} else {
				r.log.Debug("Recovery data recreated", zap.ByteString("recoveryData", marshalledSecretHashMap))
				if err := r.store.PersistRecoveryData(marshalledSecretHashMap); err != nil {
					r.log.Error("Failed to persist recreated recovery data", zap.Error(err))
				}
			}
		}

		return 0, recoveredKey, nil
	}

	r.log.Warn("Provided secrets so far couldn't decrypt the ciphertext. Please provide more secrets.", zap.Int("secretsProvided", r.correctSecrets))
	return secretsRemaining, nil, nil
}

// validateSecretLength checks whether a provided secret has a valid length (either [recoveryKeySize] bytes or [recoveryKeySizeLegacy] for backwards compatibility),
// and the length matches the length of previously provided secrets (if any).
// This is needed to keep backwards compatible with deployments started before v1.9.0 that still use a 16 byte sealing key.
func (r *MultiPartyRecovery) validateSecretLength(secret []byte) error {
	if len(secret) != RecoveryKeySizeLegacy && len(secret) != RecoveryKeySize {
		return errors.New("invalid secret length")
	}
	if len(r.providedSecrets) != 0 && len(r.providedSecrets[0]) != len(secret) {
		return fmt.Errorf("recovery secrets must match in length: provided secret has length %d, but previous provided secrets have length %d", len(secret), len(r.providedSecrets[0]))
	}
	return nil
}

// validateSecretLengthShamir checks whether a provided secret has the valid length for Shamir's secret sharing ([recoveryKeySize] + 1 byte).
func (r *MultiPartyRecovery) validateSecretLengthShamir(secret []byte) error {
	if len(secret) != RecoveryKeySize+1 {
		return errors.New("invalid secret length")
	}
	if len(r.providedSecrets) != 0 && len(r.providedSecrets[0]) != len(secret) {
		return fmt.Errorf("recovery secrets must match in length: provided secret has length %d, but previous provided secrets have length %d", len(secret), len(r.providedSecrets[0]))
	}
	return nil
}

// store is the store whose key should be recovered.
type store interface {
	GetCiphertext() ([]byte, error)
	TestKey(key, ciphertext []byte) bool
	PersistRecoveryData(data []byte) error
}

func generateMultiPartyRecoveryKey(recoveryKeys map[string]string, log *zap.Logger) ([]byte, map[string][]byte, map[string]bool, error) {
	log.Debug("Generating multi-party encryption key", zap.Int("recoveryKeys", len(recoveryKeys)))
	secretMap := make(map[string][]byte, len(recoveryKeys))
	secretHashMap := make(map[string]bool, len(recoveryKeys))
	combinedRecoveryKey := make([]byte, RecoveryKeySize)

	for index, singleRecoveryKey := range recoveryKeys {
		log.Debug("Generating key share for encryption key", zap.String("recoveryKey", index))
		// Retrieve RSA public key for potential key recovery
		recoveryK, err := ccrypto.ParseRSAPublicKeyFromPEM(singleRecoveryKey)
		if err != nil {
			return nil, nil, nil, err
		}

		// Generate a secret which will be encrypted with a single recovery public key
		newSecret, err := generateRandomKey()
		if err != nil {
			return nil, nil, nil, err
		}

		// Update combined key used to encrypt the real encryption key
		combinedRecoveryKey, err = util.XORBytes(combinedRecoveryKey, newSecret)
		if err != nil {
			return nil, nil, nil, err
		}

		// Save encrypted secret with corresponding public key
		recoveryData, err := util.EncryptOAEP(recoveryK, newSecret)
		if err != nil {
			return nil, nil, nil, err
		}

		// Save encrypted secret in the map returned to the user & hash of the unencrypted secret in another map stored next to the sealed state
		secretHash := Hash(newSecret)
		secretMap[index] = recoveryData
		secretHashMap[secretHash] = true
		log.Debug("Key share generated", zap.String("recoveryKey", index), zap.String("secretHash", secretHash))
	}

	return combinedRecoveryKey, secretMap, secretHashMap, nil
}

func generateShamirRecoveryKey(recoveryKeys map[string]string, recoveryThreshold uint, log *zap.Logger) ([]byte, map[string][]byte, map[string]bool, error) {
	log.Debug("Generating Shamir's secret sharing encryption key", zap.Int("recoveryKeys", len(recoveryKeys)), zap.Uint("recoveryThreshold", recoveryThreshold))
	secretMap := make(map[string][]byte, len(recoveryKeys))
	secretHashMap := make(map[string]bool, len(recoveryKeys))

	// Generate the encryption key to be shared
	encryptionKey, err := generateRandomKey()
	if err != nil {
		return nil, nil, nil, err
	}

	// Generate shares for recovering the key
	shares, err := shamir.Split(encryptionKey, len(recoveryKeys), int(recoveryThreshold))
	if err != nil {
		return nil, nil, nil, err
	}

	// Assign shares to recovery keys
	var shareIdx int
	for index, singleRecoveryKey := range recoveryKeys {
		recoveryK, err := ccrypto.ParseRSAPublicKeyFromPEM(singleRecoveryKey)
		if err != nil {
			return nil, nil, nil, err
		}

		share := shares[shareIdx]

		recoveryData, err := util.EncryptOAEP(recoveryK, share)
		if err != nil {
			return nil, nil, nil, err
		}

		shareHash := Hash(share)
		secretMap[index] = recoveryData
		secretHashMap[shareHash] = true
		log.Debug("Shamir share assigned", zap.String("recoveryKey", index), zap.String("shareHash", shareHash))
		shareIdx++
	}

	return encryptionKey, secretMap, secretHashMap, nil
}
