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
	"github.com/edgelesssys/marblerun/coordinator/user"
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
	store interface {
		Get(string) ([]byte, error)
		Put(string, []byte) error
	}
}

// getActivations returns activations for a given Marble from store
func (s storeWrapper) getActivations(marbleType string) (uint, error) {
	request := strings.Join([]string{requestActivations, marbleType}, ":")
	rawActivations, err := s.store.Get(request)
	if err != nil {
		return 0, err
	}

	activations, err := strconv.ParseUint(string(rawActivations), 16, 64)
	return uint(activations), err
}

// putActivations saves activations of a given Marble to store
func (s storeWrapper) putActivations(marbleType string, activations uint) error {
	request := strings.Join([]string{requestActivations, marbleType}, ":")
	rawActivations := []byte(strconv.FormatUint(uint64(activations), 16))

	return s.store.Put(request, rawActivations)
}

// incrementActivations is a wrapper for get/put activations to increment the value for one marble
func (s storeWrapper) incrementActivations(marbleType string) error {
	activations, err := s.getActivations(marbleType)
	if err != nil && !store.IsStoreValueUnsetError(err) {
		return err
	}
	activations++
	return s.putActivations(marbleType, activations)
}

// getCertificate returns a certificate from store
func (s storeWrapper) getCertificate(certType string) (*x509.Certificate, error) {
	request := strings.Join([]string{requestCert, certType}, ":")
	rawCert, err := s.store.Get(request)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(rawCert)
}

// putCertificate saves a certificate to store
func (s storeWrapper) putCertificate(certType string, cert *x509.Certificate) error {
	request := strings.Join([]string{requestCert, certType}, ":")
	return s.store.Put(request, cert.Raw)
}

// getPrivK returns a private key from store
func (s storeWrapper) getPrivK(keyType string) (*ecdsa.PrivateKey, error) {
	request := strings.Join([]string{requestPrivKey, keyType}, ":")
	rawKey, err := s.store.Get(request)
	if err != nil {
		return nil, err
	}

	return x509.ParseECPrivateKey(rawKey)
}

// putPrivK saves a private key to store
func (s storeWrapper) putPrivK(keyType string, privK *ecdsa.PrivateKey) error {
	rawKey, err := x509.MarshalECPrivateKey(privK)
	if err != nil {
		return err
	}

	request := strings.Join([]string{requestPrivKey, keyType}, ":")
	return s.store.Put(request, rawKey)
}

// getManifest loads a manifest by type and marshalls it to manifest.Manifest
func (s storeWrapper) getManifest() (*manifest.Manifest, error) {
	var manifest manifest.Manifest
	rawManifest, err := s.getRawManifest()
	if err != nil {
		// return uninitialized manifest if non was set with error
		return &manifest, err
	}
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		return nil, err
	}

	return &manifest, nil
}

// getRawManifest returns the raw main or update manifest from store
func (s storeWrapper) getRawManifest() ([]byte, error) {
	return s.store.Get(requestManifest)
}

// putRawManifest saves the raw main or update manifest to store
func (s storeWrapper) putRawManifest(manifest []byte) error {
	return s.store.Put(requestManifest, manifest)
}

// getSecret returns a secret from store
func (s storeWrapper) getSecret(secretType string) (manifest.Secret, error) {
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
func (s storeWrapper) putSecret(secretType string, secret manifest.Secret) error {
	rawSecret, err := json.Marshal(secret)
	if err != nil {
		return err
	}

	request := strings.Join([]string{requestSecret, secretType}, ":")
	return s.store.Put(request, rawSecret)
}

// getSecretMap returns a map of all shared and user-defined Marblerun secrets
func (s storeWrapper) getSecretMap() (map[string]manifest.Secret, error) {
	secretMap := map[string]manifest.Secret{}

	manifest, err := s.getManifest()
	if err != nil {
		return nil, err
	}

	for k, v := range manifest.Secrets {
		if v.Shared || v.UserDefined {
			// if a secret is not set, then this will add an empty secret
			secretMap[k], err = s.getSecret(k)
			if err != nil {
				if !store.IsStoreValueUnsetError(err) {
					return nil, err
				}
			}
		}
	}

	return secretMap, nil
}

// getState returns the state from store
func (s storeWrapper) getState() (state, error) {
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
func (s storeWrapper) putState(currState state) error {
	rawState := []byte(strconv.Itoa(int(currState)))
	return s.store.Put("state", rawState)
}

// getUser returns user information from store
func (s storeWrapper) getUser(userName string) (*user.User, error) {
	request := strings.Join([]string{requestUser, userName}, ":")
	rawUserData, err := s.store.Get(request)
	if err != nil {
		return nil, err
	}
	var loadedUser user.User
	if err := json.Unmarshal(rawUserData, &loadedUser); err != nil {
		return nil, err
	}
	return &loadedUser, nil
}

// putUser saves user information to store
func (s storeWrapper) putUser(newUser *user.User) error {
	request := strings.Join([]string{requestUser, newUser.Name()}, ":")
	rawUserData, err := json.Marshal(newUser)
	if err != nil {
		return err
	}
	return s.store.Put(request, rawUserData)
}
