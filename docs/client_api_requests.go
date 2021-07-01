package docs

import (
	"github.com/edgelesssys/marblerun/coordinator/manifest"
)

// swagger:parameters secretGet
type SecretGetRequest struct {
	// in:query
	// collection format: multi
	// items.minItems: 1
	S []string `json:"s"`
}

// swagger:parameters manifestPost updatePost
type ManifestPostRequest struct {
	// in:body
	Manifest manifest.Manifest
}

// Userers This is the start of the description This is the start of the description This is the start of the description
// User represents the user for this application This is the start of the description
// swagger:model
type Userers struct {
	// the id for this user
	//
	// required: true
	// min: 1
	ID int64 `json:"id"`

	// the name for this user
	// required: true
	// min length: 3
	Name string `json:"name"`
}
