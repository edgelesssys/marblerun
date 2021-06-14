// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package user

import (
	"encoding/json"
	"testing"

	"github.com/edgelesssys/marblerun/test"
	"github.com/stretchr/testify/assert"
)

func TestUserPermissions(t *testing.T) {
	assert := assert.New(t)

	adminTestCert, _ := test.MustSetupTestCerts(test.RecoveryPrivateKey)
	userName := "test-user"
	testResource := "testResource"
	testPermission := NewPermission(testResource, []string{"perm-1", "perm-2"})

	testUser := NewUser(userName, adminTestCert)
	testUser.Assign(testPermission)

	assert.Equal(*adminTestCert, *testUser.Certificate())
	assert.Equal(userName, testUser.Name())
	assert.Equal(testPermission, testUser.Permissions()[testResource])

	ok := testUser.IsGranted(NewPermission(testResource, []string{"perm-1"}))
	assert.True(ok)
	ok = testUser.IsGranted(NewPermission(testResource, []string{"perm-1", "perm-2"}))
	assert.True(ok)
	ok = testUser.IsGranted(NewPermission(testResource, []string{"perm-1", "perm-2", "perm-3"}))
	assert.False(ok)
	ok = testUser.IsGranted(NewPermission(testResource, []string{"perm-3"}))
	assert.False(ok)
	ok = testUser.IsGranted(NewPermission("unkownResource", []string{"perm-2"}))
	assert.False(ok)
}

func TestMarshal(t *testing.T) {
	assert := assert.New(t)
	adminTestCert, _ := test.MustSetupTestCerts(test.RecoveryPrivateKey)
	userName := "test-user"
	testResource := "testResource"
	testPermission := NewPermission(testResource, []string{"perm-1", "perm-2"})

	testUser := NewUser(userName, adminTestCert)
	testUser.Assign(testPermission)

	marshaledUser, err := json.Marshal(testUser)
	assert.NoError(err)

	unmarshaledUser := &User{}
	err = json.Unmarshal(marshaledUser, unmarshaledUser)
	assert.NoError(err)
	assert.Equal(testUser.name, unmarshaledUser.name)
	assert.Equal(*testUser.certificate, *unmarshaledUser.certificate)
	assert.Equal(testUser.permissions, unmarshaledUser.permissions)
}
