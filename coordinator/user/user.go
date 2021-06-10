// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package user

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
)

const (
	permissionSetSecret     = "SetSecret"
	permissionReadSecret    = "ReadSecret"
	permissionAllowedUpdate = "Update"
)

// MarblerunUser represents a privileged user of Marblerun
type MarblerunUser struct {
	name string
	// certificate is the users certificate, used for authentication
	certificate *x509.Certificate
	// permissions of the user
	permissions map[string]MarblerunPermission
}

// NewMarblerunUser creates a new user based on data from manifest.User
func NewMarblerunUser(name string, certificate *x509.Certificate) *MarblerunUser {
	newUser := &MarblerunUser{
		name:        name,
		certificate: certificate,
		permissions: make(map[string]MarblerunPermission),
	}
	return newUser
}

// Assign adds a new permission to the user
func (u *MarblerunUser) Assign(p MarblerunPermission) {
	u.permissions[p.ID()] = p
}

// IsGranted returns true if the user has the requested permission
func (u MarblerunUser) IsGranted(p MarblerunPermission) bool {
	q, ok := u.permissions[p.ID()]
	if !ok {
		return false
	}
	return q.match(p)
}

// Name returns the name of a user
func (u MarblerunUser) Name() string {
	return u.name
}

// Permissions returns a users permissions
func (u MarblerunUser) Permissions() map[string]MarblerunPermission {
	return u.permissions
}

// Certificate returns a users certificate
func (u MarblerunUser) Certificate() *x509.Certificate {
	return u.certificate
}

// MarblerunPermission represents the permissions of a Marblerun user
type MarblerunPermission struct {
	permissionID string
	resourceID   map[string]bool
}

// NewMarblerunPermission creates a new permission, granting access to resources grouped by permissionID
func NewMarblerunPermission(permissionID string, resourceIDs []string) MarblerunPermission {
	newPermission := MarblerunPermission{
		permissionID: permissionID,
		resourceID:   make(map[string]bool),
	}
	for _, v := range resourceIDs {
		newPermission.resourceID[v] = true
	}
	return newPermission
}

// ID returns the permissionID
func (p MarblerunPermission) ID() string {
	return p.permissionID
}

// Match returns true if a is a subgroup of p
func (p MarblerunPermission) match(q MarblerunPermission) bool {
	if p.permissionID != q.ID() {
		return false
	}
	for k := range q.resourceID {
		if !p.resourceID[k] {
			return false
		}
	}
	return true
}

// GenerateUsersFromManifest creates users and permissions from a map of manifest.User
func GenerateUsersFromManifest(rawUsers map[string]manifest.User) ([]*MarblerunUser, error) {
	// Parse & write X.509 user data from manifest
	users := make([]*MarblerunUser, 0, len(rawUsers))
	for name, userData := range rawUsers {
		block, _ := pem.Decode([]byte(userData.Certificate))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		newUser := NewMarblerunUser(name, cert)
		newUser.Assign(NewMarblerunPermission(permissionSetSecret, userData.SetSecrets))
		newUser.Assign(NewMarblerunPermission(permissionReadSecret, userData.ReadSecrets))
		newUser.Assign(NewMarblerunPermission(permissionAllowedUpdate, userData.AllowedUpdates))
		users = append(users, newUser)
	}
	return users, nil
}
