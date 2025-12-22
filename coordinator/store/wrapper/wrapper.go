/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package wrapper

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/store/request"
	"github.com/edgelesssys/marblerun/coordinator/user"
)

// WrapTransaction initializes a transaction using the given handle,
// and returns a wrapper for the transaction, as well as rollback and commit functions.
func WrapTransaction(ctx context.Context, txHandle transactionHandle,
) (wrapper Wrapper, rollback func(), commit func(context.Context) error, err error) {
	tx, err := txHandle.BeginTransaction(ctx)
	if err != nil {
		return Wrapper{}, nil, nil, err
	}
	return New(tx), tx.Rollback, tx.Commit, nil
}

// Wrapper wraps store functions to provide a more convenient interface,
// and provides a type-safe way to access the store.
type Wrapper struct {
	store dataStore
}

// New creates a new Wrapper for a store or transaction.
func New(store dataStore) Wrapper {
	return Wrapper{store}
}

// GetIterator returns a wrapped iterator from store.
func (s Wrapper) GetIterator(prefix string) (Iterator, error) {
	iter, err := s.store.Iterator(prefix)
	return Iterator{iter, prefix}, err
}

// GetActivations returns activations for a given Marble from store.
func (s Wrapper) GetActivations(marbleType string) (uint, error) {
	request := strings.Join([]string{request.Activations, marbleType}, ":")
	rawActivations, err := s.store.Get(request)
	if errors.Is(err, store.ErrValueUnset) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}

	activations, err := strconv.ParseUint(string(rawActivations), 16, 64)
	return uint(activations), err
}

// IncrementActivations is a wrapper for get/put activations to increment the value for one marble.
func (s Wrapper) IncrementActivations(marbleType string) error {
	activations, err := s.GetActivations(marbleType)
	if err != nil && !errors.Is(err, store.ErrValueUnset) {
		return err
	}
	activations++
	request := strings.Join([]string{request.Activations, marbleType}, ":")
	rawActivations := []byte(strconv.FormatUint(uint64(activations), 16))

	return s.store.Put(request, rawActivations)
}

// DeleteActivation deletes an activation from the store.
func (s Wrapper) DeleteActivation(marbleType string) error {
	return s.store.Delete(strings.Join([]string{request.Activations, marbleType}, ":"))
}

// GetCertificate returns a certificate from store.
func (s Wrapper) GetCertificate(certType string) (*x509.Certificate, error) {
	request := strings.Join([]string{request.Certificate, certType}, ":")
	rawCert, err := s.store.Get(request)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(rawCert)
}

// PutCertificate saves a certificate to store.
func (s Wrapper) PutCertificate(certType string, cert *x509.Certificate) error {
	request := strings.Join([]string{request.Certificate, certType}, ":")
	return s.store.Put(request, cert.Raw)
}

// DeleteCertificate deletes a certificate from the store.
func (s Wrapper) DeleteCertificate(certType string) error {
	return s.store.Delete(strings.Join([]string{request.Certificate, certType}, ":"))
}

// GetInfrastructure returns infrastructure information from store.
func (s Wrapper) GetInfrastructure(infraName string) (quote.InfrastructureProperties, error) {
	var infra quote.InfrastructureProperties
	err := s.get(request.Infrastructure, infraName, &infra)
	return infra, err
}

// PutInfrastructure saves infrastructure information to store.
func (s Wrapper) PutInfrastructure(infraName string, infra quote.InfrastructureProperties) error {
	return s.put(request.Infrastructure, infraName, infra)
}

// DeleteInfrastructure deletes an infrastructure from the store.
func (s Wrapper) DeleteInfrastructure(infraName string) error {
	return s.store.Delete(strings.Join([]string{request.Infrastructure, infraName}, ":"))
}

// GetMarble returns information for a specific Marble from store.
func (s Wrapper) GetMarble(marbleName string) (manifest.Marble, error) {
	var marble manifest.Marble
	err := s.get(request.Marble, marbleName, &marble)
	return marble, err
}

// PutMarble saves Marble information to store.
func (s Wrapper) PutMarble(marbleName string, marble manifest.Marble) error {
	return s.put(request.Marble, marbleName, marble)
}

// DeleteMarble deletes a marble from the store.
func (s Wrapper) DeleteMarble(marbleType string) error {
	return s.store.Delete(strings.Join([]string{request.Marble, marbleType}, ":"))
}

// GetPackage returns a Package from store.
func (s Wrapper) GetPackage(pkgName string) (quote.PackageProperties, error) {
	var pkg quote.PackageProperties
	err := s.get(request.Package, pkgName, &pkg)
	return pkg, err
}

// PutPackage saves a Package to store.
func (s Wrapper) PutPackage(pkgName string, pkg quote.PackageProperties) error {
	return s.put(request.Package, pkgName, pkg)
}

// DeletePackage deletes a package from the store.
func (s Wrapper) DeletePackage(packageName string) error {
	return s.store.Delete(strings.Join([]string{request.Package, packageName}, ":"))
}

// GetPrivateKey returns a private key from store.
func (s Wrapper) GetPrivateKey(keyType string) (*ecdsa.PrivateKey, error) {
	request := strings.Join([]string{request.PrivateKey, keyType}, ":")
	rawKey, err := s.store.Get(request)
	if err != nil {
		return nil, err
	}

	return x509.ParseECPrivateKey(rawKey)
}

// PutPrivateKey saves a private key to store.
func (s Wrapper) PutPrivateKey(keyType string, privK *ecdsa.PrivateKey) error {
	rawKey, err := x509.MarshalECPrivateKey(privK)
	if err != nil {
		return err
	}

	request := strings.Join([]string{request.PrivateKey, keyType}, ":")
	return s.store.Put(request, rawKey)
}

// GetManifest loads the manifest and marshalls it to manifest.Manifest.
func (s Wrapper) GetManifest() (manifest.Manifest, error) {
	var manifest manifest.Manifest
	rawManifest, err := s.GetRawManifest()
	if err != nil {
		return manifest, err
	}

	err = json.Unmarshal(rawManifest, &manifest)
	return manifest, err
}

// GetRawManifest returns the raw manifest from store.
func (s Wrapper) GetRawManifest() ([]byte, error) {
	return s.store.Get(request.Manifest)
}

// PutRawManifest saves the raw manifest to store.
func (s Wrapper) PutRawManifest(manifest []byte) error {
	return s.store.Put(request.Manifest, manifest)
}

// GetManifestSignature returns the ecdsa signature of the original manifest from store.
func (s Wrapper) GetManifestSignature() ([]byte, error) {
	return s.store.Get(request.ManifestSignature)
}

// PutManifestSignature saves the manifests signature to store.
func (s Wrapper) PutManifestSignature(manifestSignature []byte) error {
	return s.store.Put(request.ManifestSignature, manifestSignature)
}

// GetRootSecret returns the Coordinator's root secret.
// Falls back to using the coordinator root private key for backwards compatibility if not set.
func (s Wrapper) GetRootSecret() ([]byte, error) {
	rootSecret, err := s.store.Get(request.RootSecret)
	if err != nil {
		if !errors.Is(err, store.ErrValueUnset) {
			return nil, err
		}
		// Backwards compatibility: If root secret is not set, use the coordinator root private key
		rootPrivK, err := s.GetPrivateKey(constants.SKCoordinatorRootKey)
		if err != nil {
			return nil, err
		}
		rootSecret = rootPrivK.D.Bytes()
	}
	return rootSecret, nil
}

// PutRootSecret saves the Coordinator's root secret to store.
func (s Wrapper) PutRootSecret(rootSecret []byte) error {
	return s.store.Put(request.RootSecret, rootSecret)
}

// GetPreviousRootSecret returns the previous Coordinator's root secret.
func (s Wrapper) GetPreviousRootSecret() ([]byte, error) {
	return s.store.Get(request.PreviousRootSecret)
}

// PutPreviousRootSecret saves the previous Coordinator's root secret to store.
func (s Wrapper) PutPreviousRootSecret(previousRootSecret []byte) error {
	return s.store.Put(request.PreviousRootSecret, previousRootSecret)
}

// GetSecret returns a secret from store.
func (s Wrapper) GetSecret(secretName string) (manifest.Secret, error) {
	var loadedSecret manifest.Secret
	err := s.get(request.Secret, secretName, &loadedSecret)
	return loadedSecret, err
}

// PutSecret saves a secret to store.
func (s Wrapper) PutSecret(secretName string, secret manifest.Secret) error {
	return s.put(request.Secret, secretName, secret)
}

// DeleteSecret deletes a secret from the store.
func (s Wrapper) DeleteSecret(secretName string) error {
	return s.store.Delete(strings.Join([]string{request.Secret, secretName}, ":"))
}

// GetPreviousSecret returns a previous secret from store.
func (s Wrapper) GetPreviousSecret(secretName string) (manifest.Secret, error) {
	var loadedSecret manifest.Secret
	err := s.get(request.PreviousSecret, secretName, &loadedSecret)
	return loadedSecret, err
}

// PutPreviousSecret saves a previous secret to store.
func (s Wrapper) PutPreviousSecret(secretName string, secret manifest.Secret) error {
	return s.put(request.PreviousSecret, secretName, secret)
}

// DeletePreviousSecret deletes a previous secret from the store.
func (s Wrapper) DeletePreviousSecret(secretName string) error {
	return s.store.Delete(strings.Join([]string{request.PreviousSecret, secretName}, ":"))
}

// GetSecretMap returns a map of all secrets.
func (s Wrapper) GetSecretMap() (map[string]manifest.Secret, error) {
	return s.getSecretMap(request.Secret, s.GetSecret)
}

// GetPreviousSecretMap returns a map of all previous secrets.
func (s Wrapper) GetPreviousSecretMap() (map[string]manifest.Secret, error) {
	return s.getSecretMap(request.PreviousSecret, s.GetPreviousSecret)
}

// GetState returns the state from store.
func (s Wrapper) GetState() (state.State, error) {
	rawState, err := s.store.Get("state")
	if err != nil {
		return -1, err
	}

	currState, err := strconv.Atoi(string(rawState))
	if err != nil {
		return -1, err
	}

	return state.State(currState), nil
}

// PutState saves the state to store.
func (s Wrapper) PutState(currState state.State) error {
	rawState := []byte(strconv.Itoa(int(currState)))
	return s.store.Put("state", rawState)
}

// GetTLS returns a named t-TLS config from store.
func (s Wrapper) GetTLS(tagName string) (manifest.TLStag, error) {
	var tag manifest.TLStag
	err := s.get(request.TLS, tagName, &tag)
	return tag, err
}

// PutTLS saves a t-TLS config to store.
func (s Wrapper) PutTLS(tagName string, tag manifest.TLStag) error {
	return s.put(request.TLS, tagName, tag)
}

// DeleteTLS deletes a TLS certificate from the store.
func (s Wrapper) DeleteTLS(tagName string) error {
	return s.store.Delete(strings.Join([]string{request.TLS, tagName}, ":"))
}

// GetUpdateLog returns the update log from store.
func (s Wrapper) GetUpdateLog() (string, error) {
	log, err := s.store.Get(request.UpdateLog)
	return string(log), err
}

// PutUpdateLog saves the update log to store.
func (s Wrapper) PutUpdateLog(updateLog string) error {
	return s.store.Put(request.UpdateLog, []byte(updateLog))
}

// AppendUpdateLog appends new entries to the log and saves it to store.
func (s Wrapper) AppendUpdateLog(updateLog string) error {
	oldLog, err := s.GetUpdateLog()
	if err != nil {
		return err
	}
	return s.PutUpdateLog(oldLog + updateLog)
}

// GetUser returns user information from store.
func (s Wrapper) GetUser(userName string) (*user.User, error) {
	loadedUser := &user.User{}
	err := s.get(request.User, userName, loadedUser)
	return loadedUser, err
}

// PutUser saves user information to store.
func (s Wrapper) PutUser(newUser *user.User) error {
	return s.put(request.User, newUser.Name(), newUser)
}

// DeleteUser deletes a user from the store.
func (s Wrapper) DeleteUser(username string) error {
	return s.store.Delete(strings.Join([]string{request.User, username}, ":"))
}

// SetMonotonicCounter increases the value of a monotonic counter in the store and returns the previous value.
func (s Wrapper) SetMonotonicCounter(name string, value uint64) (uint64, error) {
	request := request.MonotonicCounter + ":" + name

	var currentValue uint64
	if raw, err := s.store.Get(request); err == nil {
		currentValue = binary.LittleEndian.Uint64(raw)
	} else if !errors.Is(err, store.ErrValueUnset) {
		return 0, err
	}

	if value > currentValue {
		if err := s.store.Put(request, binary.LittleEndian.AppendUint64(nil, value)); err != nil {
			return 0, err
		}
	}

	return currentValue, nil
}

func (s Wrapper) getSecretMap(requestResource string, getSecret func(string) (manifest.Secret, error)) (map[string]manifest.Secret, error) {
	iter, err := s.GetIterator(requestResource)
	if err != nil {
		return nil, err
	}

	secretMap := map[string]manifest.Secret{}
	for iter.HasNext() {
		// all secrets (user-defined and private only as uninitialized placeholders) are set with the initial manifest
		// if we encounter an error here something went wrong with the store, or the provided list was faulty
		name, err := iter.GetNext()
		if err != nil {
			return nil, err
		}
		secretMap[name], err = getSecret(name)
		if err != nil {
			return nil, err
		}
	}
	return secretMap, nil
}

// put is the default method for marshaling and saving data to store.
func (s Wrapper) put(requestType, requestResource string, target interface{}) error {
	request := strings.Join([]string{requestType, requestResource}, ":")
	rawData, err := json.Marshal(target)
	if err != nil {
		return err
	}
	return s.store.Put(request, rawData)
}

// get is the default method for loading and unmarshaling data from store.
func (s Wrapper) get(requestType, requestResource string, target interface{}) error {
	request := strings.Join([]string{requestType, requestResource}, ":")
	rawData, err := s.store.Get(request)
	if err != nil {
		return err
	}
	return json.Unmarshal(rawData, target)
}

// Iterator is a wrapper for the Iterator interface.
type Iterator struct {
	iterator store.Iterator
	prefix   string
}

// GetNext returns the next key in the iterator.
func (i Iterator) GetNext() (string, error) {
	key, err := i.iterator.GetNext()
	return strings.TrimPrefix(key, i.prefix+":"), err
}

// HasNext returns true if there are more keys in the iterator.
func (i Iterator) HasNext() bool {
	return i.iterator.HasNext()
}

type dataStore interface {
	// Get returns a value from store by key
	Get(string) ([]byte, error)
	// Put saves a value to store by key
	Put(string, []byte) error
	// Delete removes a value from store by key
	Delete(string) error
	// Iterator returns an Iterator for a given prefix
	Iterator(string) (store.Iterator, error)
}

type transactionHandle interface {
	BeginTransaction(context.Context) (store.Transaction, error)
}
