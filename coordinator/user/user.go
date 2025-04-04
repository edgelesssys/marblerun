/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package user

import (
	"crypto/x509"
	"encoding/json"
)

// Permissions available to users.
const (
	PermissionWriteSecret    = "writesecret"
	PermissionReadSecret     = "readsecret"
	PermissionUpdatePackage  = "updatesecurityversion"
	PermissionUpdateManifest = "updatemanifest"
)

// User represents a privileged user of MarbleRun.
type User struct {
	name string
	// certificate is the users certificate, used for authentication
	certificate *x509.Certificate
	// permissions of the user
	permissions map[string]Permission
}

// NewUser creates a new user.
func NewUser(name string, certificate *x509.Certificate) *User {
	newUser := &User{
		name:        name,
		certificate: certificate,
		permissions: make(map[string]Permission),
	}
	return newUser
}

// Assign adds a new permission to the user.
func (u *User) Assign(p Permission) {
	if _, ok := u.permissions[p.ID()]; !ok {
		u.permissions[p.ID()] = p
	} else {
		for k, v := range p.ResourceID {
			u.permissions[p.ID()].ResourceID[k] = u.permissions[p.ID()].ResourceID[k] || v
		}
	}
}

// IsGranted returns true if the user has the requested permission.
func (u *User) IsGranted(p Permission) bool {
	q, ok := u.permissions[p.ID()]
	if !ok {
		return false
	}
	return q.match(p)
}

// Name returns the name of a user.
func (u *User) Name() string {
	return u.name
}

// Permissions returns a users permissions.
func (u *User) Permissions() map[string]Permission {
	return u.permissions
}

// Certificate returns a users certificate.
func (u *User) Certificate() *x509.Certificate {
	return u.certificate
}

// MarshalJSON implements the json.Marshaler interface.
func (u *User) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Name        string
		Certificate []byte
		Permissions map[string]Permission
	}{
		Name:        u.name,
		Certificate: u.certificate.Raw,
		Permissions: u.permissions,
	})
}

// UnmarshalJSON implements the json.Marshaler interface.
func (u *User) UnmarshalJSON(data []byte) error {
	tmp := &struct {
		Name        string
		Certificate []byte
		Permissions map[string]Permission
	}{}
	if err := json.Unmarshal(data, tmp); err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(tmp.Certificate)
	if err != nil {
		return err
	}

	u.name = tmp.Name
	u.permissions = tmp.Permissions
	u.certificate = cert
	return nil
}

// Equal returns true if both users are the same.
func (u *User) Equal(other *User) bool {
	// Check if the other user is granted
	// all permissions of the current user
	for _, perm := range u.permissions {
		if !other.IsGranted(perm) {
			return false
		}
	}
	// Check if the current user is granted
	// all permissions of the other user
	for _, perm := range other.permissions {
		if !u.IsGranted(perm) {
			return false
		}
	}

	return u.name == other.name && u.certificate.Equal(other.certificate)
}

// Permission represents the permissions of a MarbleRun user.
type Permission struct {
	PermissionID string
	ResourceID   map[string]bool
}

// NewPermission creates a new permission, granting access to resources grouped by permissionID.
func NewPermission(permissionID string, resourceIDs []string) Permission {
	newPermission := Permission{
		PermissionID: permissionID,
		ResourceID:   make(map[string]bool),
	}
	for _, v := range resourceIDs {
		newPermission.ResourceID[v] = true
	}
	return newPermission
}

// ID returns the permissionID.
func (p Permission) ID() string {
	return p.PermissionID
}

// Match returns true if a is a subgroup of p.
func (p Permission) match(q Permission) bool {
	if p.PermissionID != q.ID() {
		return false
	}
	for k := range q.ResourceID {
		if !p.ResourceID[k] {
			return false
		}
	}
	return true
}
