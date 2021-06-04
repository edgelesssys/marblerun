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
	"github.com/edgelesssys/marblerun/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// just to test current implementation of storewrapper
func TestStoreWrapper(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	c := NewCoreWithMocks()

	// creating a new core should have set root and intermediate certs/keys
	_, err := c.store.getCertificate("root")
	assert.NoError(err)
	_, err = c.store.getPrivK("root")
	assert.NoError(err)

	rawManifest := []byte(test.ManifestJSON)
	curState := stateAcceptingManifest
	testActivations := uint(5)
	testSecret := manifest.Secret{
		Type:   "symmetric-key",
		Size:   16,
		Shared: true,
	}
	someCert, somePrivK, err := generateCert([]string{"example.com"}, coordinatorName, nil, nil)
	require.NoError(err)
	testUserCert, _, err := generateCert([]string{"example.com"}, "test-user", nil, nil)
	require.NoError(err)
	testUser := &marblerunUser{name: "test-user", certificate: testUserCert}

	// save values to store
	err = c.store.putActivations("test-marble", testActivations)
	assert.NoError(err)
	err = c.store.putCertificate("some-cert", someCert)
	assert.NoError(err)
	err = c.store.putPrivK("some-key", somePrivK)
	assert.NoError(err)
	err = c.store.putRawManifest("main", rawManifest)
	assert.NoError(err)
	err = c.store.putSecret("test-secret", testSecret)
	assert.NoError(err)
	err = c.store.putState(curState)
	assert.NoError(err)
	err = c.store.putUser(testUser)
	assert.NoError(err)

	// see if we can retrieve them again
	savedAc, err := c.store.getActivations("test-marble")
	assert.NoError(err)
	assert.Equal(testActivations, savedAc)
	savedCert, err := c.store.getCertificate("some-cert")
	assert.NoError(err)
	assert.Equal(someCert, savedCert)
	savedKey, err := c.store.getPrivK("some-key")
	assert.NoError(err)
	assert.Equal(somePrivK, savedKey)
	savedManifest, err := c.store.getRawManifest("main")
	assert.NoError(err)
	assert.Equal(rawManifest, savedManifest)
	savedSecret, err := c.store.getSecret("test-secret")
	assert.NoError(err)
	assert.Equal(testSecret, savedSecret)
	savedState, err := c.store.getState()
	assert.NoError(err)
	assert.Equal(curState, savedState)
	savedUser, err := c.store.getUser("test-user")
	assert.NoError(err)
	assert.Equal(testUser, savedUser)
}

func TestStoreWrapperDefaults(t *testing.T) {
	assert := assert.New(t)

	c := NewCoreWithMocks()

	// values for root / intermediate and state should be set by core init function
	_, err := c.store.getCertificate("root")
	assert.NoError(err)
	_, err = c.store.getCertificate("intermediate")
	assert.NoError(err)
	_, err = c.store.getPrivK("root")
	assert.NoError(err)
	_, err = c.store.getPrivK("intermediate")
	assert.NoError(err)
	state, err := c.store.getState()
	assert.NoError(err)
	assert.Equal(stateAcceptingManifest, state)

	// Nothing else was set, should always return error
	_, err = c.store.getActivations("test-marble")
	assert.True(store.IsStoreValueUnsetError(err), "activations were not unset")
	_, err = c.store.getRawManifest("main")
	assert.True(store.IsStoreValueUnsetError(err), "raw manifest was not unset")
	_, err = c.store.getSecret("test-secret")
	assert.True(store.IsStoreValueUnsetError(err), "[test-secret] was not unset")
	_, err = c.store.getUser("test-user")
	assert.True(store.IsStoreValueUnsetError(err), "[test-user] was not unset")
}

func TestStoreWrapperRollback(t *testing.T) {
	assert := assert.New(t)

	c := NewCoreWithMocks()

	activations := uint(15)
	err := c.store.putActivations("test-marble-1", activations)
	assert.NoError(err)
	err = c.store.sealState([]byte{0x00})
	assert.NoError(err)

	err = c.store.putActivations("test-marble-2", uint(20))
	assert.NoError(err)

	_, _, _, err = c.store.loadState()
	assert.NoError(err)
	val, err := c.store.getActivations("test-marble-1")
	assert.NoError(err)
	assert.Equal(activations, val)
	_, err = c.store.getActivations("test-marble-2")
	assert.True(store.IsStoreValueUnsetError(err))
}
