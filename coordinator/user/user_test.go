// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package user

import (
	"encoding/json"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserPermissions(t *testing.T) {
	assert := assert.New(t)

	adminTestCert, _ := test.MustSetupTestCerts(test.RecoveryPrivateKey)
	userName := "test-user"
	testResource := "testResource"
	testPermission := NewMarblerunPermission(testResource, []string{"perm-1", "perm-2"})

	testUser := NewMarblerunUser(userName, adminTestCert)
	testUser.Assign(testPermission)

	assert.Equal(*adminTestCert, *testUser.Certificate())
	assert.Equal(userName, testUser.Name())
	assert.Equal(testUser.Permissions()[testResource], testPermission)

	ok := testUser.IsGranted(NewMarblerunPermission(testResource, []string{"perm-1"}))
	assert.True(ok)
	ok = testUser.IsGranted(NewMarblerunPermission(testResource, []string{"perm-1", "perm-2"}))
	assert.True(ok)
	ok = testUser.IsGranted(NewMarblerunPermission(testResource, []string{"perm-1", "perm-2", "perm-3"}))
	assert.False(ok)
	ok = testUser.IsGranted(NewMarblerunPermission(testResource, []string{"perm-3"}))
	assert.False(ok)
	ok = testUser.IsGranted(NewMarblerunPermission("unkownResource", []string{"perm-2"}))
	assert.False(ok)
}

func TestGenerateUsersFromManifest(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	var manifest manifest.Manifest
	err := json.Unmarshal([]byte(test.ManifestJSONWithRecoveryKey), &manifest)
	require.NoError(err)

	newUsers, err := GenerateUsersFromManifest(manifest.Users)
	assert.NoError(err)
	assert.Equal(len(manifest.Users), len(newUsers))
}
