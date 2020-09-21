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
func (c *Core) SetManifest(ctx context.Context, rawManifest []byte) error {
	defer c.mux.Unlock()
	if err := c.requireState(acceptingManifest); err != nil {
		return err
	}
	if err := json.Unmarshal(rawManifest, &c.manifest); err != nil {
		return err
	}
	c.rawManifest = rawManifest
	// TODO: sanitize manifest AB#166
	c.advanceState()
	c.sealState()
	return nil
}

// GetCertQuote gets the Coordinators certificate and corresponding quote (containing the cert)
func (c *Core) GetCertQuote(ctx context.Context) (string, []byte, error) {
	cert, err := c.getCert(ctx)
	if err != nil {
		return "", nil, err
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "Certificate", Bytes: cert.Raw})
	if len(pemCert) <= 0 {
		return "", nil, errors.New("pem.EncodeToMemory failed")
	}
	strCert := string(pemCert)
	return strCert, c.quote, nil
}

// GetManifestSignature returns the hash of the manifest
func (c *Core) GetManifestSignature(ctx context.Context) []byte {
	if c.state == uninitialized || c.state == acceptingManifest {
		return nil
	}
	hash := sha256.Sum256(c.rawManifest)
	return hash[:]
}

// GetStatus IS A DUMMY IMPLEMENTATION. TODO
func (c *Core) GetStatus(ctx context.Context) (status string, err error) {
	status, err = c.getStatus(ctx)
	if err != nil {
		return "", err
	}

	return status, nil

}
