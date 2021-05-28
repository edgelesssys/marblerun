// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// just to test current implementation of storewrapper
func TestStoreWrapper(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	c := NewCoreWithMocks()

	rawManifest := []byte(test.ManifestJSON)
	curState := stateAcceptingManifest
	testActivations := uint64(5)
	testSecret := manifest.Secret{
		Type:   "symmetric-key",
		Size:   16,
		Shared: true,
	}
	rootCert, rootPrivK, err := generateCert([]string{"example.com"}, coordinatorName, nil, nil)
	require.NoError(err)
	testUser, _, err := generateCert([]string{"example.com"}, "test-user", nil, nil)
	require.NoError(err)

	// save values to store
	err = c.putStoreActivations("test-marble", testActivations)
	assert.NoError(err)
	err = c.putStoreCertificate("root", rootCert)
	assert.NoError(err)
	err = c.putStorePrivK("root", rootPrivK)
	assert.NoError(err)
	err = c.putStoreRawManifest("main", rawManifest)
	assert.NoError(err)
	err = c.putStoreSecret("test-secret", testSecret)
	assert.NoError(err)
	err = c.putStoreState(curState)
	assert.NoError(err)
	err = c.putStoreUser("test-user", testUser)
	assert.NoError(err)

	// see if we can retrieve them again
	savedAc, err := c.getStoreActivations("test-marble")
	assert.NoError(err)
	assert.Equal(testActivations, savedAc)
	savedCert, err := c.getStoreCertificate("root")
	assert.NoError(err)
	assert.Equal(rootCert, savedCert)
	savedKey, err := c.getStorePrivK("root")
	assert.NoError(err)
	assert.Equal(rootPrivK, savedKey)
	savedManifest, err := c.getStoreRawManifest("main")
	assert.NoError(err)
	assert.Equal(rawManifest, savedManifest)
	savedSecret, err := c.getStoreSecret("test-secret")
	assert.NoError(err)
	assert.Equal(testSecret, savedSecret)
	savedState, err := c.getStoreState()
	assert.NoError(err)
	assert.Equal(curState, savedState)
	savedUser, err := c.getStoreUser("test-user")
	assert.NoError(err)
	assert.Equal(testUser, savedUser)
}

func TestStoreWrapperFailing(t *testing.T) {
	assert := assert.New(t)

	c := NewCoreWithMocks()

	// Nothing was set, should always return error
	_, err := c.getStoreActivations("test-marble")
	assert.Error(err)
	_, err = c.getStoreCertificate("root")
	assert.Error(err)
	_, err = c.getStorePrivK("root")
	assert.Error(err)
	_, err = c.getStoreRawManifest("main")
	assert.Error(err)
	_, err = c.getStoreSecret("test-secret")
	assert.Error(err)
	_, err = c.getStoreState()
	assert.Error(err)
	_, err = c.getStoreUser("test-user")
	assert.Error(err)
}
