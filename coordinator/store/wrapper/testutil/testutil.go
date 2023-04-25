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

// GetState returns the current state of the store.
func GetState(t *testing.T, txHandle transactionHandle) state.State {
	t.Helper()
	tx, rollback, _, err := wrapper.WrapTransaction(context.Background(), txHandle)
	require.NoError(t, err)
	defer rollback()
	state, err := tx.GetState()
	require.NoError(t, err)
	return state
}

// GetCertificate returns the certificate with the given name.
func GetCertificate(t *testing.T, txHandle transactionHandle, name string) *x509.Certificate {
	t.Helper()
	tx, rollback, _, err := wrapper.WrapTransaction(context.Background(), txHandle)
	require.NoError(t, err)
	defer rollback()
	cert, err := tx.GetCertificate(name)
	require.NoError(t, err)
	return cert
}

// GetPrivateKey returns the private key with the given name.
func GetPrivateKey(t *testing.T, txHandle transactionHandle, name string) *ecdsa.PrivateKey {
	t.Helper()
	tx, rollback, _, err := wrapper.WrapTransaction(context.Background(), txHandle)
	require.NoError(t, err)
	defer rollback()
	privKey, err := tx.GetPrivateKey(name)
	require.NoError(t, err)
	return privKey
}

// GetSecretMap returns a map of all secrets in the store.
func GetSecretMap(t *testing.T, txHandle transactionHandle) map[string]manifest.Secret {
	t.Helper()
	tx, rollback, _, err := wrapper.WrapTransaction(context.Background(), txHandle)
	require.NoError(t, err)
	defer rollback()
	secretMap, err := tx.GetSecretMap()
	require.NoError(t, err)
	return secretMap
}

// GetUser returns the user with the given name.
func GetUser(t *testing.T, txHandle transactionHandle, name string) *user.User {
	t.Helper()
	tx, rollback, _, err := wrapper.WrapTransaction(context.Background(), txHandle)
	require.NoError(t, err)
	defer rollback()
	user, err := tx.GetUser(name)
	require.NoError(t, err)
	return user
}

// GetPackage returns the package with the given name.
func GetPackage(t *testing.T, txHandle transactionHandle, name string) quote.PackageProperties {
	t.Helper()
	tx, rollback, _, err := wrapper.WrapTransaction(context.Background(), txHandle)
	require.NoError(t, err)
	defer rollback()
	pkg, err := tx.GetPackage(name)
	require.NoError(t, err)
	return pkg
}

// GetManifest returns the manifest.
func GetManifest(t *testing.T, txHandle transactionHandle) manifest.Manifest {
	t.Helper()
	tx, rollback, _, err := wrapper.WrapTransaction(context.Background(), txHandle)
	require.NoError(t, err)
	defer rollback()
	manifest, err := tx.GetManifest()
	require.NoError(t, err)
	return manifest
}

// GetRawManifest returns the raw manifest.
func GetRawManifest(t *testing.T, txHandle transactionHandle) []byte {
	t.Helper()
	tx, rollback, _, err := wrapper.WrapTransaction(context.Background(), txHandle)
	require.NoError(t, err)
	defer rollback()
	manifest, err := tx.GetRawManifest()
	require.NoError(t, err)
	return manifest
}

// GetManifestSignature returns the manifest signature.
func GetManifestSignature(t *testing.T, txHandle transactionHandle) []byte {
	t.Helper()
	tx, rollback, _, err := wrapper.WrapTransaction(context.Background(), txHandle)
	require.NoError(t, err)
	defer rollback()
	sig, err := tx.GetManifestSignature()
	require.NoError(t, err)
	return sig
}
