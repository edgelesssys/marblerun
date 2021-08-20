package docs

import (
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/server"
)

// swagger:response ErrorResponse
type ErrorResponse struct {
	// in:body
	Body struct {
		// example: error
		Status string
		Data   interface{}
		// example: InternalServerError
		Message string
	}
}

// swagger:response SuccessResponse
type SuccessResponse struct {
	// in:body
	Body struct {
		// example: success
		Status string
		Data   interface{}
	}
}

// swagger:response StatusResponse
type StatusResponse struct {
	// in:body
	Body struct {
		// example: success
		Status string
		Data   server.StatusResp
	}
}

// swagger:response ManifestResponse
type ManifestResponse struct {
	// in:body
	Body struct {
		// example: success
		Status string
		Data   server.ManifestSignatureResp
	}
}

// swagger:response CertQuoteResponse
type CertQuoteResponse struct {
	// in:body
	Body struct {
		// example: success
		Status string
		Data   server.CertQuoteResp
	}
}

// swagger:response UpdateLogResponse
type UpdateLogResponse struct {
	// in:body
	Body struct {
		// example: success
		Status string
		// example: SecurityVersion increased {"user": "someuser", "package": "somepackage", "new version": 4}
		Data string
	}
}

// swagger:response RecoveryDataResponse
type RecoveryDataResponse struct {
	// in:body
	Body struct {
		// example: success
		Status string
		Data   server.RecoveryDataResp
	}
}

// swagger:response RecoveryStatusResponse
type RecoveryStatusResponse struct {
	// in:body
	Body struct {
		// example: success
		Status string
		Data   server.RecoveryStatusResp
	}
}

// swagger:response SecretsMapResponse
type SecretsMapResponse struct {
	// in:body
	Body struct {
		// example: success
		Status string
		// A map containing key-value pairs for the requested secret.
		Data map[string]manifest.Secret
	}
}
