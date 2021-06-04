// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/store"
)

const (
	requestActivations = "activations"
	requestCert        = "certificate"
	requestManifest    = "manifest"
	requestPrivKey     = "privateKey"
	requestSecret      = "secret"
	requestState       = "state"
	requestUser        = "user"
)

// storeWrapper is a wrapper for the store interface
type storeWrapper struct {
	store store.Store
}

// newStoreWrapper creates and initialses a new storeWrapper object
func newStoreWrapper(store store.Store) *storeWrapper {
	return &storeWrapper{store: store}
}

// getActivations returns activations for a given Marble from store
func (s *storeWrapper) getActivations(marbleType string) (uint, error) {
	request := strings.Join([]string{requestActivations, marbleType}, ":")
	rawActivations, err := s.store.Get(request)
	if err != nil {
		return 0, err
	}

	activations, err := strconv.ParseUint(string(rawActivations), 16, 64)
	return uint(activations), err
}

// putActivations saves activations of a given Marble to store
func (s *storeWrapper) putActivations(marbleType string, activations uint) error {
	request := strings.Join([]string{requestActivations, marbleType}, ":")
	rawActivations := []byte(strconv.FormatUint(uint64(activations), 16))

	return s.store.Put(request, rawActivations)
}

// incrementActivations is a wrapper for get/put activations to increment the value for one marble
func (s *storeWrapper) incrementActivations(marbleType string) error {
	activations, err := s.getActivations(marbleType)
	if err != nil {
		return err
	}
	activations++
	return s.putActivations(marbleType, activations)
}

// getCertificate returns a certificate from store
func (s *storeWrapper) getCertificate(certType string) (*x509.Certificate, error) {
	request := strings.Join([]string{requestCert, certType}, ":")
	rawCert, err := s.store.Get(request)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(rawCert)
}

// putCertificate saves a certificate to store
func (s *storeWrapper) putCertificate(certType string, cert *x509.Certificate) error {
	request := strings.Join([]string{requestCert, certType}, ":")
	return s.store.Put(request, cert.Raw)
}

// getPrivK returns a private key from store
func (s *storeWrapper) getPrivK(keyType string) (*ecdsa.PrivateKey, error) {
	request := strings.Join([]string{requestPrivKey, keyType}, ":")
	rawKey, err := s.store.Get(request)
	if err != nil {
		return nil, err
	}

	return x509.ParseECPrivateKey(rawKey)
}

// putPrivK saves a private key to store
func (s *storeWrapper) putPrivK(keyType string, privK *ecdsa.PrivateKey) error {
	rawKey, err := x509.MarshalECPrivateKey(privK)
	if err != nil {
		return err
	}

	request := strings.Join([]string{requestPrivKey, keyType}, ":")
	return s.store.Put(request, rawKey)
}

// getManifest loads a manifest by type and marshalls it to manifest.Manifest
func (s *storeWrapper) getManifest(manifestType string) (*manifest.Manifest, error) {
	var manifest manifest.Manifest
	rawManifest, err := s.getRawManifest(manifestType)
	if err == nil {
		if err := json.Unmarshal(rawManifest, &manifest); err != nil {
			return nil, err
		}
	} else if !store.IsStoreValueUnsetError(err) {
		return nil, err
	}

	return &manifest, nil
}

// getRawManifest returns the raw main or update manifest from store
func (s *storeWrapper) getRawManifest(manifestType string) ([]byte, error) {
	request := strings.Join([]string{requestManifest, manifestType}, ":")
	return s.store.Get(request)
}

// putRawManifest saves the raw main or update manifest to store
func (s *storeWrapper) putRawManifest(manifestType string, manifest []byte) error {
	request := strings.Join([]string{requestManifest, manifestType}, ":")
	return s.store.Put(request, manifest)
}

// getSecret returns a secret from store
func (s *storeWrapper) getSecret(secretType string) (manifest.Secret, error) {
	var loadedSecret manifest.Secret
	request := strings.Join([]string{requestSecret, secretType}, ":")
	rawSecret, err := s.store.Get(request)
	if err != nil {
		return loadedSecret, err
	}

	err = json.Unmarshal(rawSecret, &loadedSecret)
	return loadedSecret, err
}

// putSecret saves a secret to store
func (s *storeWrapper) putSecret(secretType string, secret manifest.Secret) error {
	rawSecret, err := json.Marshal(secret)
	if err != nil {
		return err
	}

	request := strings.Join([]string{requestSecret, secretType}, ":")
	return s.store.Put(request, rawSecret)
}

// getSecretMap returns a map of all Marblerun secrets
func (s *storeWrapper) getSecretMap() (map[string]manifest.Secret, error) {
	secretMap := map[string]manifest.Secret{}

	manifest, err := s.getManifest("main")
	if err != nil {
		return nil, err
	}

	for key := range manifest.Secrets {
		if manifest.Secrets[key].Shared {
			secretMap[key], err = s.getSecret(key)
			if err != nil {
				return nil, err
			}
		}
	}

	return secretMap, nil
}

// getState returns the state from store
func (s *storeWrapper) getState() (state, error) {
	rawState, err := s.store.Get("state")
	if err != nil {
		return -1, err
	}

	currState, err := strconv.Atoi(string(rawState))
	if err != nil {
		return -1, err
	}

	return state(currState), nil
}

// putState saves the state to store
func (s *storeWrapper) putState(currState state) error {
	rawState := []byte(strconv.Itoa(int(currState)))
	return s.store.Put("state", rawState)
}

// getUser returns user information from store
// will be changed in the future to return permissions etc. instead of just certificate
func (s *storeWrapper) getUser(userName string) (*marblerunUser, error) {
	request := strings.Join([]string{requestUser, userName}, ":")
	rawCert, err := s.store.Get(request)
	if err != nil {
		return nil, err
	}

	userCert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return nil, err
	}

	return &marblerunUser{name: userName, certificate: userCert}, nil
}

// putUser saves user information to store
// will be changed in the future to set permissions etc. instead of just certificate
func (s *storeWrapper) putUser(user *marblerunUser) error {
	request := strings.Join([]string{requestUser, user.name}, ":")
	return s.store.Put(request, user.certificate.Raw)
}

// loadState loads the store state and returns recoveryData
func (s *storeWrapper) loadState() ([]byte, *manifest.Manifest, *manifest.Manifest, error) {
	recoveryData, err := s.store.LoadState()
	if err != nil {
		return recoveryData, nil, nil, err
	}

	// load main manifest if it was set
	mainManifest, err := s.getManifest("main")
	if err != nil {
		return recoveryData, nil, nil, err
	}

	// load update manifest it it was set
	updateManifest, err := s.getManifest("update")
	if err != nil {
		return recoveryData, nil, nil, err
	}

	return recoveryData, mainManifest, updateManifest, nil
}

// sealState seals the store state
func (s *storeWrapper) sealState(recoveryData []byte) error {
	return s.store.SealState(recoveryData)
}

// setEncryptionKey sets the encryption key of store
func (s *storeWrapper) setEncryptionKey(encryptionKey []byte) error {
	return s.store.SetEncryptionKey(encryptionKey)
}
