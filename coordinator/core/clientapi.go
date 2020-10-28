package core

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
)

// ClientCore provides the core functionality for the client. It can be used by e.g. a http server
type ClientCore interface {
	SetManifest(ctx context.Context, rawManifest []byte) error
	GetCertQuote(ctx context.Context) (cert string, certQuote []byte, err error)
	GetManifestSignature(ctx context.Context) (manifestSignature []byte)
	GetStatus(ctx context.Context) (status string, err error)
}

// SetManifest sets the manifest, once and for all
//
// rawManifest is the manifest of type Manifest in JSON format.
func (c *Core) SetManifest(ctx context.Context, rawManifest []byte) error {
	defer c.mux.Unlock()
	if err := c.requireState(acceptingManifest); err != nil {
		return err
	}
	var manifest Manifest
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		return err
	}
	if err := manifest.Check(ctx); err != nil {
		return err
	}
	c.manifest = manifest
	c.rawManifest = rawManifest

	c.advanceState()
	c.sealState()
	return nil
}

// GetCertQuote gets the Coordinators certificate and corresponding quote (containing the cert)
//
// Returns the a remote attestation quote of its own certificate alongside this certificate that allows to verify the Coordinator's integrity and authentication for use of the ClientAPI.
func (c *Core) GetCertQuote(ctx context.Context) (string, []byte, error) {
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
	if len(pemCert) <= 0 {
		return "", nil, errors.New("pem.EncodeToMemory failed")
	}
	strCert := string(pemCert)
	return strCert, c.quote, nil
}

// GetManifestSignature returns the hash of the manifest
//
// Returns a SHA256 hash of the active manifest.
func (c *Core) GetManifestSignature(ctx context.Context) []byte {
	c.mux.Lock()
	rawManifest := c.rawManifest
	c.mux.Unlock()
	if rawManifest == nil {
		return nil
	}
	hash := sha256.Sum256(rawManifest)
	return hash[:]
}

// GetStatus is not implemented. It will return status information about the state of the mesh in the future.
func (c *Core) GetStatus(ctx context.Context) (status string, err error) {
	status, err = c.getStatus(ctx)
	if err != nil {
		return "", err
	}

	return status, nil

}
