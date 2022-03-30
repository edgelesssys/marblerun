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
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/user"
)

const (
	requestActivations       = "activations"
	requestCert              = "certificate"
	requestInfrastructure    = "infrastructure"
	requestManifest          = "manifest"
	requestManifestSignature = "manifestSignature"
	requestMarble            = "marble"
	requestPackage           = "package"
	requestPrivKey           = "privateKey"
	requestSecret            = "secret"
	requestState             = "state"
	requestTLS               = "TLS"
	requestUser              = "user"
	requestUpdateLog         = "updateLog"
)

// storeWrapper is a wrapper for the store interface.
type storeWrapper struct {
	store interface {
		Get(string) ([]byte, error)
		Put(string, []byte) error
		Iterator(string) (store.Iterator, error)
	}
}

// iteratorWrapper is a wrapper for the Iterator interface.
type iteratorWrapper struct {
	iterator store.Iterator
	prefix   string
}

func (i iteratorWrapper) GetNext() (string, error) {
	key, err := i.iterator.GetNext()
	return strings.TrimPrefix(key, i.prefix+":"), err
}

func (i iteratorWrapper) HasNext() bool {
	return i.iterator.HasNext()
}

// getIterator returns a wrapped iterator from store.
func (s storeWrapper) getIterator(prefix string) (iteratorWrapper, error) {
	iter, err := s.store.Iterator(prefix)
	return iteratorWrapper{iter, prefix}, err
}

// getActivations returns activations for a given Marble from store.
func (s storeWrapper) getActivations(marbleType string) (uint, error) {
	request := strings.Join([]string{requestActivations, marbleType}, ":")
	rawActivations, err := s.store.Get(request)
	if err != nil {
		return 0, err
	}

	activations, err := strconv.ParseUint(string(rawActivations), 16, 64)
	return uint(activations), err
}

// putActivations saves activations of a given Marble to store.
func (s storeWrapper) putActivations(marbleType string, activations uint) error {
	request := strings.Join([]string{requestActivations, marbleType}, ":")
	rawActivations := []byte(strconv.FormatUint(uint64(activations), 16))

	return s.store.Put(request, rawActivations)
}

// incrementActivations is a wrapper for get/put activations to increment the value for one marble.
func (s storeWrapper) incrementActivations(marbleType string) error {
	activations, err := s.getActivations(marbleType)
	if err != nil && !store.IsStoreValueUnsetError(err) {
		return err
	}
	activations++
	return s.putActivations(marbleType, activations)
}

// getCertificate returns a certificate from store.
func (s storeWrapper) getCertificate(certType string) (*x509.Certificate, error) {
	request := strings.Join([]string{requestCert, certType}, ":")
	rawCert, err := s.store.Get(request)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(rawCert)
}

// putCertificate saves a certificate to store.
func (s storeWrapper) putCertificate(certType string, cert *x509.Certificate) error {
	request := strings.Join([]string{requestCert, certType}, ":")
	return s.store.Put(request, cert.Raw)
}

// getInfrastructure returns infrastructure information from store.
func (s storeWrapper) getInfrastructure(infraName string) (quote.InfrastructureProperties, error) {
	var infra quote.InfrastructureProperties
	err := s._get(requestInfrastructure, infraName, &infra)
	return infra, err
}

// putInfrastructure saves infrastructure information to store.
func (s storeWrapper) putInfrastructure(infraName string, infra quote.InfrastructureProperties) error {
	return s._put(requestInfrastructure, infraName, infra)
}

// getMarble returns information for a specific Marble from store.
func (s storeWrapper) getMarble(marbleName string) (manifest.Marble, error) {
	var marble manifest.Marble
	err := s._get(requestMarble, marbleName, &marble)
	return marble, err
}

// putMarble saves Marble information to store.
func (s storeWrapper) putMarble(marbleName string, marble manifest.Marble) error {
	return s._put(requestMarble, marbleName, marble)
}

// getPackage returns a Package from store.
func (s storeWrapper) getPackage(pkgName string) (quote.PackageProperties, error) {
	var pkg quote.PackageProperties
	err := s._get(requestPackage, pkgName, &pkg)
	return pkg, err
}

// putPackage saves a Package to store.
func (s storeWrapper) putPackage(pkgName string, pkg quote.PackageProperties) error {
	return s._put(requestPackage, pkgName, pkg)
}

// getPrivK returns a private key from store.
func (s storeWrapper) getPrivK(keyType string) (*ecdsa.PrivateKey, error) {
	request := strings.Join([]string{requestPrivKey, keyType}, ":")
	rawKey, err := s.store.Get(request)
	if err != nil {
		return nil, err
	}

	return x509.ParseECPrivateKey(rawKey)
}

// putPrivK saves a private key to store.
func (s storeWrapper) putPrivK(keyType string, privK *ecdsa.PrivateKey) error {
	rawKey, err := x509.MarshalECPrivateKey(privK)
	if err != nil {
		return err
	}

	request := strings.Join([]string{requestPrivKey, keyType}, ":")
	return s.store.Put(request, rawKey)
}

// getManifest loads the manifest and marshalls it to manifest.Manifest.
func (s storeWrapper) getManifest() (manifest.Manifest, error) {
	var manifest manifest.Manifest
	rawManifest, err := s.getRawManifest()
	if err != nil {
		return manifest, err
	}

	err = json.Unmarshal(rawManifest, &manifest)
	return manifest, err
}

// getRawManifest returns the raw manifest from store.
func (s storeWrapper) getRawManifest() ([]byte, error) {
	return s.store.Get(requestManifest)
}

// putRawManifest saves the raw manifest to store.
func (s storeWrapper) putRawManifest(manifest []byte) error {
	return s.store.Put(requestManifest, manifest)
}

// getManifestSignature returns manifests signature from store.
func (s storeWrapper) getManifestSignature() ([]byte, error) {
	return s.store.Get(requestManifestSignature)
}

// putManifestSignature saves the manifests signature to store.
func (s storeWrapper) putManifestSignature(manifestSignature []byte) error {
	return s.store.Put(requestManifestSignature, manifestSignature)
}

// getSecret returns a secret from store.
func (s storeWrapper) getSecret(secretName string) (manifest.Secret, error) {
	var loadedSecret manifest.Secret
	err := s._get(requestSecret, secretName, &loadedSecret)
	return loadedSecret, err
}

// putSecret saves a secret to store.
func (s storeWrapper) putSecret(secretName string, secret manifest.Secret) error {
	return s._put(requestSecret, secretName, secret)
}

// getSecretMap returns a map of all secrets.
func (s storeWrapper) getSecretMap() (map[string]manifest.Secret, error) {
	iter, err := s.getIterator(requestSecret)
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
		secretMap[name], err = s.getSecret(name)
		if err != nil {
			return nil, err
		}
	}
	return secretMap, nil
}

// getState returns the state from store.
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

// putState saves the state to store.
func (s storeWrapper) putState(currState state) error {
	rawState := []byte(strconv.Itoa(int(currState)))
	return s.store.Put("state", rawState)
}

// getTLS returns a named t-TLS config from store.
func (s storeWrapper) getTLS(tagName string) (manifest.TLStag, error) {
	var tag manifest.TLStag
	err := s._get(requestTLS, tagName, &tag)
	return tag, err
}

// putTLS saves a t-TLS config to store.
func (s storeWrapper) putTLS(tagName string, tag manifest.TLStag) error {
	return s._put(requestTLS, tagName, tag)
}

// getUpdateLog returns the update log from store.
func (s storeWrapper) getUpdateLog() (string, error) {
	log, err := s.store.Get(requestUpdateLog)
	return string(log), err
}

// putUpdateLog saves the update log to store.
func (s storeWrapper) putUpdateLog(updateLog string) error {
	return s.store.Put(requestUpdateLog, []byte(updateLog))
}

// appendUpdateLog appends new entries to the log and saves it to store.
func (s storeWrapper) appendUpdateLog(updateLog string) error {
	oldLog, err := s.getUpdateLog()
	if err != nil {
		return err
	}
	return s.putUpdateLog(oldLog + updateLog)
}

// getUser returns user information from store.
func (s storeWrapper) getUser(userName string) (*user.User, error) {
	loadedUser := &user.User{}
	err := s._get(requestUser, userName, loadedUser)
	return loadedUser, err
}

// putUser saves user information to store.
func (s storeWrapper) putUser(newUser *user.User) error {
	return s._put(requestUser, newUser.Name(), newUser)
}

// _put is the default method for marshaling and saving data to store.
func (s storeWrapper) _put(requestType, requestResource string, target interface{}) error {
	request := strings.Join([]string{requestType, requestResource}, ":")
	rawData, err := json.Marshal(target)
	if err != nil {
		return err
	}
	return s.store.Put(request, rawData)
}

// _get is the default method for loading and unmarshaling data from store.
func (s storeWrapper) _get(requestType, requestResource string, target interface{}) error {
	request := strings.Join([]string{requestType, requestResource}, ":")
	rawData, err := s.store.Get(request)
	if err != nil {
		return err
	}
	return json.Unmarshal(rawData, target)
}
