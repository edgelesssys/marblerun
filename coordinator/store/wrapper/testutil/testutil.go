// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package testutil provides utility functions to access store values in unit tests.
package testutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper"
	"github.com/edgelesssys/marblerun/coordinator/user"
	"github.com/stretchr/testify/require"
)

type transactionHandle interface {
	BeginTransaction(context.Context) (store.Transaction, error)
}

// GetActivations returns the number of activations for a given Marble.
func GetActivations(t *testing.T, txHandle transactionHandle, name string) uint {
	return get(t, txHandle, func(tx wrapper.Wrapper) (uint, error) {
		return tx.GetActivations(name)
	})
}

// GetCertificate returns the certificate with the given name.
func GetCertificate(t *testing.T, txHandle transactionHandle, name string) *x509.Certificate {
	return get(t, txHandle, func(tx wrapper.Wrapper) (*x509.Certificate, error) {
		return tx.GetCertificate(name)
	})
}

// GetInfrastructure returns infrastructure information.
func GetInfrastructure(t *testing.T, txHandle transactionHandle, name string) quote.InfrastructureProperties {
	return get(t, txHandle, func(tx wrapper.Wrapper) (quote.InfrastructureProperties, error) {
		return tx.GetInfrastructure(name)
	})
}

// GetMarble returns the marble with the given name.
func GetMarble(t *testing.T, txHandle transactionHandle, name string) manifest.Marble {
	return get(t, txHandle, func(tx wrapper.Wrapper) (manifest.Marble, error) {
		return tx.GetMarble(name)
	})
}

// GetPackage returns the package with the given name.
func GetPackage(t *testing.T, txHandle transactionHandle, name string) quote.PackageProperties {
	return get(t, txHandle, func(tx wrapper.Wrapper) (quote.PackageProperties, error) {
		return tx.GetPackage(name)
	})
}

// GetPrivateKey returns the private key with the given name.
func GetPrivateKey(t *testing.T, txHandle transactionHandle, name string) *ecdsa.PrivateKey {
	return get(t, txHandle, func(tx wrapper.Wrapper) (*ecdsa.PrivateKey, error) {
		return tx.GetPrivateKey(name)
	})
}

// GetManifest returns the manifest.
func GetManifest(t *testing.T, txHandle transactionHandle) manifest.Manifest {
	return get(t, txHandle, func(tx wrapper.Wrapper) (manifest.Manifest, error) {
		return tx.GetManifest()
	})
}

// GetRawManifest returns the raw manifest.
func GetRawManifest(t *testing.T, txHandle transactionHandle) []byte {
	return get(t, txHandle, func(tx wrapper.Wrapper) ([]byte, error) {
		return tx.GetRawManifest()
	})
}

// GetManifestSignature returns the manifest signature.
func GetManifestSignature(t *testing.T, txHandle transactionHandle) []byte {
	return get(t, txHandle, func(tx wrapper.Wrapper) ([]byte, error) {
		return tx.GetManifestSignature()
	})
}

// GetSecret returns the secret with the given name.
func GetSecret(t *testing.T, txHandle transactionHandle, name string) manifest.Secret {
	return get(t, txHandle, func(tx wrapper.Wrapper) (manifest.Secret, error) {
		return tx.GetSecret(name)
	})
}

// GetSecretMap returns a map of all secrets in the store.
func GetSecretMap(t *testing.T, txHandle transactionHandle) map[string]manifest.Secret {
	return get(t, txHandle, func(tx wrapper.Wrapper) (map[string]manifest.Secret, error) {
		return tx.GetSecretMap()
	})
}

// GetState returns the current state of the store.
func GetState(t *testing.T, txHandle transactionHandle) state.State {
	return get(t, txHandle, func(tx wrapper.Wrapper) (state.State, error) {
		return tx.GetState()
	})
}

// GetTLS returns the TLS config with the given name.
func GetTLS(t *testing.T, txHandle transactionHandle, name string) manifest.TLStag {
	return get(t, txHandle, func(tx wrapper.Wrapper) (manifest.TLStag, error) {
		return tx.GetTLS(name)
	})
}

// GetUpdateLog returns the update log.
func GetUpdateLog(t *testing.T, txHandle transactionHandle) string {
	return get(t, txHandle, func(tx wrapper.Wrapper) (string, error) {
		return tx.GetUpdateLog()
	})
}

// GetUser returns the user with the given name.
func GetUser(t *testing.T, txHandle transactionHandle, name string) *user.User {
	return get(t, txHandle, func(tx wrapper.Wrapper) (*user.User, error) {
		return tx.GetUser(name)
	})
}

func get[T any](t *testing.T, txHandle transactionHandle, getter func(wrapper.Wrapper) (T, error)) T {
	t.Helper()
	tx, rollback, _, err := wrapper.WrapTransaction(context.Background(), txHandle)
	require.NoError(t, err)
	defer rollback()
	val, err := getter(tx)
	require.NoError(t, err)
	return val
}
