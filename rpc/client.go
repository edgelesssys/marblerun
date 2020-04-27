package rpc

import "context"

// ClientServer defines the interface the coordinator exposes to clients via HTTP
type ClientServer interface {
	// SetManifest installs the manifest in the coordinator
	SetManifest(ctx context.Context, rawManifest []byte) error
	// GetQuote gets the quote for the coordinator's certificate
	GetQuote(ctx context.Context) ([]byte, error)
}
