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
)

const (
	requestActivations string = "activations"
	requestCert        string = "certificate"
	requestManifest    string = "manifest"
	requestPrivKey     string = "privateKey"
	requestSecret      string = "secret"
	requestState       string = "state"
	requestUser        string = "user"
)

// getStoreActivations returns activations for a given Marble from store
func (c *Core) getStoreActivations(marbleType string) (uint64, error) {
	request := strings.Join([]string{requestActivations, marbleType}, ":")
	rawActivations, err := c.store.Get(request)
	if err != nil {
		return 0, err
	}

	return strconv.ParseUint(string(rawActivations), 16, 64)
}

// putStoreActivations saves activations of a given Marble to store
func (c *Core) putStoreActivations(marbleType string, activations uint64) error {
	request := strings.Join([]string{requestActivations, marbleType}, ":")
	rawActivations := []byte(strconv.FormatUint(activations, 16))

	return c.store.Put(request, rawActivations)
}

// getStoreCertificate returns a certificate from store
func (c *Core) getStoreCertificate(certType string) (*x509.Certificate, error) {
	request := strings.Join([]string{requestCert, certType}, ":")
	rawCert, err := c.store.Get(request)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(rawCert)
}

// putStoreCertificate saves a certificate to store
func (c *Core) putStoreCertificate(certType string, cert *x509.Certificate) error {
	request := strings.Join([]string{requestCert, certType}, ":")
	return c.store.Put(request, cert.Raw)
}

// getStorePrivK returns a private key from store
func (c *Core) getStorePrivK(keyType string) (*ecdsa.PrivateKey, error) {
	request := strings.Join([]string{requestPrivKey, keyType}, ":")
	rawKey, err := c.store.Get(request)
	if err != nil {
		return nil, err
	}

	return x509.ParseECPrivateKey(rawKey)
}

// putStorePrivK saves a private key to store
func (c *Core) putStorePrivK(keyType string, privK *ecdsa.PrivateKey) error {
	rawKey, err := x509.MarshalECPrivateKey(privK)
	if err != nil {
		return err
	}

	request := strings.Join([]string{requestPrivKey, keyType}, ":")
	return c.store.Put(request, rawKey)
}

// getStoreRawManifest returns the raw main or update manifest from store
func (c *Core) getStoreRawManifest(manifestType string) ([]byte, error) {
	request := strings.Join([]string{requestManifest, manifestType}, ":")
	return c.store.Get(request)
}

// putStoreRawManifest saves the raw main or update manifest to store
func (c *Core) putStoreRawManifest(manifestType string, manifest []byte) error {
	request := strings.Join([]string{requestManifest, manifestType}, ":")
	return c.store.Put(request, manifest)
}

// getStoreSecret returns a secret from store
func (c *Core) getStoreSecret(secretType string) (manifest.Secret, error) {
	var loadedSecret manifest.Secret
	request := strings.Join([]string{requestSecret, secretType}, ":")
	rawSecret, err := c.store.Get(request)
	if err != nil {
		return loadedSecret, err
	}

	err = json.Unmarshal(rawSecret, &loadedSecret)
	return loadedSecret, err
}

// putStoreSecret saves a secret to store
func (c *Core) putStoreSecret(secretType string, secret manifest.Secret) error {
	rawSecret, err := json.Marshal(secret)
	if err != nil {
		return err
	}

	request := strings.Join([]string{requestSecret, secretType}, ":")
	return c.store.Put(request, rawSecret)
}

// getStoreState returns the state from store
func (c *Core) getStoreState() (state, error) {
	rawState, err := c.store.Get("state")
	if err != nil {
		return stateMax, err
	}

	currState, err := strconv.Atoi(string(rawState))
	if err != nil {
		return stateMax, err
	}

	return state(currState), nil
}

// putStoreState saves the state to store
func (c *Core) putStoreState(currState state) error {
	rawState := []byte(strconv.Itoa(int(currState)))
	return c.store.Put("state", rawState)
}

// getStoreUser returns user information from store
// will be changed in the future to return permissions etc. instead of just certificate
func (c *Core) getStoreUser(userType string) (*x509.Certificate, error) {
	request := strings.Join([]string{requestUser, userType}, ":")
	rawCert, err := c.store.Get(request)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(rawCert)
}

// putStoreUser saves user information to store
// will be changed in the future to set permissions etc. instead of just certificate
func (c *Core) putStoreUser(userType string, userCert *x509.Certificate) error {
	request := strings.Join([]string{requestUser, userType}, ":")
	return c.store.Put(request, userCert.Raw)
}
