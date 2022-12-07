// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package apidoc

import (
	"github.com/edgelesssys/marblerun/coordinator/manifest"
)

// swagger:parameters secretsGet
type SecretsGetRequest struct {
	// in:query
	// collection format: multi
	// items.minItems: 1
	S []string `json:"s"`
}

// swagger:parameters secretsPost
type SecretsPostRequest struct {
	// in:body
	Secrets map[string]manifest.UserSecret
}

// swagger:parameters manifestPost updatePost
type ManifestPostRequest struct {
	// in:body
	Manifest manifest.Manifest
}

// swagger:parameters recoverPost
type RecoverPostRequest struct {
	// in:body
	// The base64 decoded and decrypted recovery secret
	RecoverySecret []byte
}
