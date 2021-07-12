// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/user"
	"github.com/edgelesssys/marblerun/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreWrapper(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	c := NewCoreWithMocks()

	// creating a new core should have set root and intermediate certs/keys
	_, err := c.data.getCertificate(sKCoordinatorRootCert)
	assert.NoError(err)
	_, err = c.data.getPrivK(sKCoordinatorRootKey)
	assert.NoError(err)

	rawManifest := []byte(test.ManifestJSON)
	curState := stateAcceptingManifest
	testActivations := uint(5)
	testSecret := manifest.Secret{
		Type:   "symmetric-key",
		Size:   16,
		Shared: true,
	}
	someCert, somePrivK, err := generateCert([]string{"example.com"}, coordinatorName, nil, nil, nil)
	require.NoError(err)
	testUserCert, _, err := generateCert([]string{"example.com"}, "test-user", nil, nil, nil)
	require.NoError(err)
	testUser := user.NewUser("test-user", testUserCert)

	// save values to store
	tx, err := c.store.BeginTransaction()
	assert.NoError(err)
	txdata := storeWrapper{tx}
	assert.NoError(txdata.putActivations("test-marble", testActivations))
	assert.NoError(txdata.putCertificate("some-cert", someCert))
	assert.NoError(txdata.putPrivK("some-key", somePrivK))
	assert.NoError(txdata.putRawManifest(rawManifest))
	assert.NoError(txdata.putSecret("test-secret", testSecret))
	assert.NoError(txdata.putState(curState))
	assert.NoError(txdata.putUser(testUser))
	assert.NoError(tx.Commit())

	// see if we can retrieve them again
	savedAc, err := c.data.getActivations("test-marble")
	assert.NoError(err)
	assert.Equal(testActivations, savedAc)
	savedCert, err := c.data.getCertificate("some-cert")
	assert.NoError(err)
	assert.Equal(someCert, savedCert)
	savedKey, err := c.data.getPrivK("some-key")
	assert.NoError(err)
	assert.Equal(somePrivK, savedKey)
	savedManifest, err := c.data.getRawManifest()
	assert.NoError(err)
	assert.Equal(rawManifest, savedManifest)
	savedSecret, err := c.data.getSecret("test-secret")
	assert.NoError(err)
	assert.Equal(testSecret, savedSecret)
	savedState, err := c.data.getState()
	assert.NoError(err)
	assert.Equal(curState, savedState)
	savedUser, err := c.data.getUser("test-user")
	assert.NoError(err)
	assert.Equal(testUser, savedUser)
}

func TestStoreWrapperDefaults(t *testing.T) {
	assert := assert.New(t)

	c := NewCoreWithMocks()

	// values for root / intermediate and state should be set by core init function
	_, err := c.data.getCertificate(sKCoordinatorRootCert)
	assert.NoError(err)
	_, err = c.data.getCertificate(skCoordinatorIntermediateCert)
	assert.NoError(err)
	_, err = c.data.getPrivK(sKCoordinatorRootKey)
	assert.NoError(err)
	_, err = c.data.getPrivK(sKCoordinatorIntermediateKey)
	assert.NoError(err)
	state, err := c.data.getState()
	assert.NoError(err)
	assert.Equal(stateAcceptingManifest, state)

	// Nothing else was set, should always return error
	_, err = c.data.getActivations("test-marble")
	assert.True(store.IsStoreValueUnsetError(err), "activations were not unset")
	_, err = c.data.getRawManifest()
	assert.True(store.IsStoreValueUnsetError(err), "raw manifest was not unset")
	_, err = c.data.getSecret("test-secret")
	assert.True(store.IsStoreValueUnsetError(err), "[test-secret] was not unset")
	_, err = c.data.getUser("test-user")
	assert.True(store.IsStoreValueUnsetError(err), "[test-user] was not unset")
	_, err = c.data.getUpdateLog()
	assert.True(store.IsStoreValueUnsetError(err), "update log was not unset")
}

func TestStoreWrapperRollback(t *testing.T) {
	assert := assert.New(t)

	c := NewCoreWithMocks()

	activations := uint(15)
	tx, err := c.store.BeginTransaction()
	assert.NoError(err)
	assert.NoError(storeWrapper{tx}.putActivations("test-marble-1", activations))
	assert.NoError(tx.Commit())

	tx, err = c.store.BeginTransaction()
	assert.NoError(err)
	assert.NoError(storeWrapper{tx}.putActivations("test-marble-2", uint(20)))
	tx.Rollback()

	val, err := c.data.getActivations("test-marble-1")
	assert.NoError(err)
	assert.Equal(activations, val)
	_, err = c.data.getActivations("test-marble-2")
	assert.True(store.IsStoreValueUnsetError(err))
}
