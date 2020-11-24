// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"

	"go.uber.org/zap"
)

// ClientCore provides the core functionality for the client. It can be used by e.g. a http server
type ClientCore interface {
	SetManifest(ctx context.Context, rawManifest []byte) (recoveryDataBytes []byte, err error)
	GetCertQuote(ctx context.Context) (cert string, certQuote []byte, err error)
	GetManifestSignature(ctx context.Context) (manifestSignature []byte)
	GetStatus(ctx context.Context) (statusCode int, status string, err error)
	Recover(ctx context.Context, encryptionKey []byte) error
}

// SetManifest sets the manifest, once and for all
//
// rawManifest is the manifest of type Manifest in JSON format.
func (c *Core) SetManifest(ctx context.Context, rawManifest []byte) ([]byte, error) {
	defer c.mux.Unlock()
	if err := c.requireState(stateAcceptingManifest, stateRecovery); err != nil {
		return nil, err
	}

	var manifest Manifest
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		return nil, err
	}
	if err := manifest.Check(ctx); err != nil {
		return nil, err
	}

	// Generate secrets specified in manifest
	secrets, err := c.generateSecrets(ctx, manifest.Secrets)
	if err != nil {
		c.zaplogger.Error("Could not generate specified secrets for the given manifest.", zap.Error(err))
		return nil, err
	}

	var recoveryk *rsa.PublicKey

	// Retrieve RSA public key for potential key recovery
	if manifest.RecoveryKey != "" {
		block, _ := pem.Decode([]byte(manifest.RecoveryKey))

		if block == nil || block.Type != "PUBLIC KEY" {
			c.zaplogger.Error("Manifest supplied a key which does not appear to be a public key.")
			return nil, errors.New("invalid public key in manifest")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			c.zaplogger.Error("Could not parse public key specified in manifest.", zap.Error(err))
			return nil, err
		}
		var ok bool
		if recoveryk, ok = pub.(*rsa.PublicKey); !ok {
			c.zaplogger.Error("Public Key specified in manifest is not a RSA public key.")
			return nil, errors.New("unsupported type of public key")
		}
	}

	// Generate a new encryption key for a new manifest, as the old one might be broken
	if err := c.sealer.GenerateNewEncryptionKey(); err != nil {
		return nil, err
	}

	c.manifest = manifest
	c.rawManifest = rawManifest
	log.Println("Saving secrets in core")
	c.secrets = secrets
	log.Println(c.secrets)

	c.advanceState(stateAcceptingMarbles)
	encryptionKey, err := c.sealState()
	if err != nil {
		c.zaplogger.Error("sealState failed", zap.Error(err))
	}

	var recoveryData []byte
	if recoveryk != nil {
		recoveryData, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, recoveryk, encryptionKey, nil)
		if err != nil {
			c.zaplogger.Error("Creation of recovery data failed.", zap.Error(err))
		}
	}

	return recoveryData, nil
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

// Recover sets an encryption key (ideally decrypted from the recovery data) and tries to unseal and load a saved state again.
func (c *Core) Recover(ctx context.Context, encryptionKey []byte) error {
	defer c.mux.Unlock()
	if err := c.requireState(stateRecovery); err != nil {
		return err
	}

	if err := c.sealer.SetEncryptionKey(encryptionKey); err != nil {
		return err
	}

	cert, privk, err := c.loadState()
	if err != nil {
		return err
	}

	c.cert = cert
	c.privk = privk

	c.quote = c.generateQuote()

	return nil
}

// GetStatus returns status information about the state of the mesh.
func (c *Core) GetStatus(ctx context.Context) (statusCode int, status string, err error) {
	return c.getStatus(ctx)
}
