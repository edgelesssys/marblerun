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
