// Copyright (c) Edgeless Systems GmbH.
// Licensed under the MIT License.

package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"

	"go.uber.org/zap"
)

// ClientCore provides the core functionality for the client. It can be used by e.g. a http server
type ClientCore interface {
	SetManifest(ctx context.Context, rawManifest []byte) error
	GetCertQuote(ctx context.Context) (cert string, certQuote []byte, err error)
	GetManifestSignature(ctx context.Context) (manifestSignature []byte)
	GetStatus(ctx context.Context) (status string, err error)
	GetRecoveryData(ctx context.Context) (encodedRecoveryData string)
}

// SetManifest sets the manifest, once and for all
//
// rawManifest is the manifest of type Manifest in JSON format.
func (c *Core) SetManifest(ctx context.Context, rawManifest []byte) error {
	defer c.mux.Unlock()
	if err := c.requireState(stateAcceptingManifest); err != nil {
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

	// Retrieve RSA public key for potential key recovery
	if manifest.RecoveryKey != "" {
		block, _ := pem.Decode([]byte(manifest.RecoveryKey))

		if block == nil || block.Type != "PUBLIC KEY" {
			c.zaplogger.Warn("Manifest supplied a key which does not appear to be a public key. Will not return recovery data.")
		} else {
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				c.zaplogger.Error("Could not parse public key!", zap.Error(err))
			} else {
				switch pub.(type) {
				case *rsa.PublicKey:
					c.recoveryk = pub.(*rsa.PublicKey)
				default:
					c.zaplogger.Error("Public Key is NOT a RSA key. Will not return recovery data.")
				}
			}
		}
	}

	c.advanceState()
	encryptionKey, err := c.sealState()
	if err != nil {
		c.zaplogger.Error("sealState failed", zap.Error(err))
	}

	if c.recoveryk != nil {
		c.recoveryData, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, c.recoveryk, encryptionKey, nil)
		if err != nil {
			c.zaplogger.Error("Creation of recovery data failed.", zap.Error(err))
		}
	}

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

// GetRecoveryData returns the RSA-encrypted AES-encryption key used for saving the state on disk, in case any RSA public key was set as the recovery key in the manifest
func (c *Core) GetRecoveryData(ctx context.Context) string {
	return base64.StdEncoding.EncodeToString(c.recoveryData)
}

// GetStatus is not implemented. It will return status information about the state of the mesh in the future.
func (c *Core) GetStatus(ctx context.Context) (status string, err error) {
	status, err = c.getStatus(ctx)
	if err != nil {
		return "", err
	}

	return status, nil
}
