// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package user

import (
	"crypto/x509"
	"encoding/json"
	"testing"

	"github.com/edgelesssys/marblerun/test"
	"github.com/stretchr/testify/assert"
)

func TestUserPermissions(t *testing.T) {
	assert := assert.New(t)

	adminTestCert, _ := test.MustSetupTestCerts(test.RecoveryPrivateKey)
	userName := "test-user"
	testID := "testPermission"
	testPermission := NewPermission(testID, []string{"res-1", "res-2"})

	testUser := NewUser(userName, adminTestCert)
	testUser.Assign(testPermission)

	assert.Equal(*adminTestCert, *testUser.Certificate())
	assert.Equal(userName, testUser.Name())
	assert.Equal(testPermission, testUser.Permissions()[testID])

	ok := testUser.IsGranted(NewPermission(testID, []string{"res-1"}))
	assert.True(ok)
	ok = testUser.IsGranted(NewPermission(testID, []string{"res-1", "res-2"}))
	assert.True(ok)
	ok = testUser.IsGranted(NewPermission(testID, []string{"res-1", "res-2", "res-3"}))
	assert.False(ok)
	ok = testUser.IsGranted(NewPermission(testID, []string{"res-3"}))
	assert.False(ok)
	ok = testUser.IsGranted(NewPermission("unknownID", []string{"res-2"}))
	assert.False(ok)
}

func TestMarshal(t *testing.T) {
	assert := assert.New(t)
	adminTestCert, _ := test.MustSetupTestCerts(test.RecoveryPrivateKey)
	userName := "test-user"
	testID := "testPermission"
	testPermission := NewPermission(testID, []string{"perm-1", "perm-2"})

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

func TestEqual(t *testing.T) {
	testCases := map[string]struct {
		user1     *User
		user2     *User
		wantEqual bool
	}{
		"equal": {
			user1: &User{
				name:        "test-user",
				certificate: &x509.Certificate{Raw: []byte("test")},
				permissions: map[string]Permission{
					"perm-1": NewPermission("perm-1", []string{"res-1", "res-2"}),
				},
			},
			user2: &User{
				name:        "test-user",
				certificate: &x509.Certificate{Raw: []byte("test")},
				permissions: map[string]Permission{
					"perm-1": NewPermission("perm-1", []string{"res-1", "res-2"}),
				},
			},
			wantEqual: true,
		},
		"unequal name": {
			user1: &User{
				name:        "test-user",
				certificate: &x509.Certificate{Raw: []byte("test")},
				permissions: map[string]Permission{
					"perm-1": NewPermission("perm-1", []string{"res-1", "res-2"}),
				},
			},
			user2: &User{
				name:        "test-user-2",
				certificate: &x509.Certificate{Raw: []byte("test")},
				permissions: map[string]Permission{
					"perm-1": NewPermission("perm-1", []string{"res-1", "res-2"}),
				},
			},
			wantEqual: false,
		},
		"unequal certificate": {
			user1: &User{
				name:        "test-user",
				certificate: &x509.Certificate{Raw: []byte("test")},
				permissions: map[string]Permission{
					"perm-1": NewPermission("perm-1", []string{"res-1", "res-2"}),
				},
			},
			user2: &User{
				name:        "test-user",
				certificate: &x509.Certificate{Raw: []byte("test-2")},
				permissions: map[string]Permission{
					"perm-1": NewPermission("perm-1", []string{"res-1", "res-2"}),
				},
			},
			wantEqual: false,
		},
		"user1 lacks user2 resource permissions": {
			user1: &User{
				name:        "test-user",
				certificate: &x509.Certificate{Raw: []byte("test")},
				permissions: map[string]Permission{
					"perm-1": NewPermission("perm-1", []string{"res-1", "res-2"}),
				},
			},
			user2: &User{
				name:        "test-user",
				certificate: &x509.Certificate{Raw: []byte("test")},
				permissions: map[string]Permission{
					"perm-1": NewPermission("perm-1", []string{"res-1", "res-2", "res-3"}),
				},
			},
			wantEqual: false,
		},
		"user1 has more permissions than user2": {
			user1: &User{
				name:        "test-user",
				certificate: &x509.Certificate{Raw: []byte("test")},
				permissions: map[string]Permission{
					"perm-1": NewPermission("perm-1", []string{"res-1", "res-2"}),
					"perm-2": NewPermission("perm-2", []string{"res-3", "res-4"}),
				},
			},
			user2: &User{
				name:        "test-user",
				certificate: &x509.Certificate{Raw: []byte("test")},
				permissions: map[string]Permission{
					"perm-1": NewPermission("perm-1", []string{"res-1", "res-2"}),
				},
			},
			wantEqual: false,
		},
		"unequal permissions": {
			user1: &User{
				name:        "test-user",
				certificate: &x509.Certificate{Raw: []byte("test")},
				permissions: map[string]Permission{
					"perm-1": NewPermission("perm-1", []string{"res-1", "res-2"}),
				},
			},
			user2: &User{
				name:        "test-user",
				certificate: &x509.Certificate{Raw: []byte("test")},
				permissions: map[string]Permission{
					"perm-2": NewPermission("perm-2", []string{"res-1", "res-2"}),
				},
			},
			wantEqual: false,
		},
		"unequal resource permissions": {
			user1: &User{
				name:        "test-user",
				certificate: &x509.Certificate{Raw: []byte("test")},
				permissions: map[string]Permission{
					"perm-1": NewPermission("perm-1", []string{"res-1", "res-2"}),
				},
			},
			user2: &User{
				name:        "test-user",
				certificate: &x509.Certificate{Raw: []byte("test")},
				permissions: map[string]Permission{
					"perm-1": NewPermission("perm-1", []string{"res-1", "res-3"}),
				},
			},
			wantEqual: false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.wantEqual, tc.user1.Equal(tc.user2))
			assert.Equal(t, tc.wantEqual, tc.user2.Equal(tc.user1))
		})
	}
}
