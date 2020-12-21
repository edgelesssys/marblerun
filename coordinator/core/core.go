// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package core provides the core functionality for the Coordinator object including state transition, APIs for marbles and clients, handling of manifests and the sealing functionalities.
package core

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/util"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// Core implements the core logic of the Coordinator
type Core struct {
	cert        *x509.Certificate
	quote       []byte
	privk       *ecdsa.PrivateKey
	sealer      Sealer
	manifest    Manifest
	rawManifest []byte
	secrets     map[string]Secret
	state       state
	qv          quote.Validator
	qi          quote.Issuer
	activations map[string]uint
	mux         sync.Mutex
	zaplogger   *zap.Logger
}

// The sequence of states a Coordinator may be in
type state int

const (
	stateUninitialized state = iota
	stateRecovery
	stateAcceptingManifest
	stateAcceptingMarbles
	stateMax
)

// sealedState represents the state information, required for persistence, that gets sealed to the filesystem
type sealedState struct {
	Privk       []byte
	RawManifest []byte
	RawCert     []byte
	Secrets     map[string]Secret
	State       state
	Activations map[string]uint
}

// CoordinatorName is the name of the Coordinator. It is used as CN of the root certificate.
const CoordinatorName string = "Marblerun Coordinator"

// Needs to be paired with `defer c.mux.Unlock()`
func (c *Core) requireState(states ...state) error {
	c.mux.Lock()
	for _, s := range states {
		if s == c.state {
			return nil
		}
	}
	return errors.New("server is not in expected state")
}

func (c *Core) advanceState(newState state) {
	if !(c.state < newState && newState < stateMax) {
		panic(fmt.Errorf("cannot advance from %d to %d", c.state, newState))
	}
	c.state = newState
}

// NewCore creates and initializes a new Core object
func NewCore(dnsNames []string, qv quote.Validator, qi quote.Issuer, sealer Sealer, zapLogger *zap.Logger) (*Core, error) {
	c := &Core{
		state:       stateUninitialized,
		activations: make(map[string]uint),
		qv:          qv,
		qi:          qi,
		sealer:      sealer,
		zaplogger:   zapLogger,
	}

	zapLogger.Info("loading state")
	cert, privk, err := c.loadState()
	if err != nil {
		if err != ErrEncryptionKey {
			return nil, err
		}
		c.zaplogger.Error("Failed to decrypt sealed state. Processing with a new state. Use the /recover API endpoint to load an old state, or submit a new manifest to overwrite the old state. Look up the documentation for more information on how to proceed.")
		cert, privk, err = c.generateCert(dnsNames)
		if err != nil {
			return nil, err
		}
		c.advanceState(stateRecovery)
	} else if cert == nil {
		c.zaplogger.Info("No sealed state found. Proceeding with new state.")
		cert, privk, err = c.generateCert(dnsNames)
		if err != nil {
			return nil, err
		}
		c.advanceState(stateAcceptingManifest)
	}

	c.cert = cert
	c.privk = privk
	c.quote = c.generateQuote()

	return c, nil
}

// NewCoreWithMocks creates a new core object with quote and seal mocks for testing.
func NewCoreWithMocks() *Core {
	zapLogger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}

	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &MockSealer{}
	core, err := NewCore([]string{"localhost"}, validator, issuer, sealer, zapLogger)
	if err != nil {
		panic(err)
	}
	return core
}

// inSimulationMode returns true if we operate in OE_SIMULATION mode
func (c *Core) inSimulationMode() bool {
	return len(c.quote) == 0
}

// GetTLSConfig gets the core's TLS configuration
func (c *Core) GetTLSConfig() (*tls.Config, error) {
	return &tls.Config{
		GetCertificate: c.GetTLSCertificate,
	}, nil
}

// GetTLSCertificate creates a TLS certificate for the Coordinators self-signed x509 certificate
func (c *Core) GetTLSCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c.state == stateUninitialized {
		return nil, errors.New("don't have a cert yet")
	}
	return util.TLSCertFromDER(c.cert.Raw, c.privk), nil
}

func (c *Core) loadState() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	stateRaw, err := c.sealer.Unseal()
	if err != nil {
		return nil, nil, err
	}
	if len(stateRaw) == 0 {
		return nil, nil, nil
	}

	// load state
	c.zaplogger.Info("applying sealed state")
	var loadedState sealedState
	if err := json.Unmarshal(stateRaw, &loadedState); err != nil {
		return nil, nil, err
	}

	// set Core to loaded state
	cert, err := x509.ParseCertificate(loadedState.RawCert)
	if err != nil {
		return nil, nil, err
	}
	privk, err := x509.ParseECPrivateKey(loadedState.Privk)
	if err != nil {
		return nil, nil, err
	}

	if err := json.Unmarshal(loadedState.RawManifest, &c.manifest); err != nil {
		return nil, nil, err
	}
	c.rawManifest = loadedState.RawManifest

	c.state = loadedState.State
	c.activations = loadedState.Activations
	c.secrets = loadedState.Secrets
	return cert, privk, err
}

func (c *Core) sealState() ([]byte, error) {
	// marshal private key
	x509Encoded, err := x509.MarshalECPrivateKey(c.privk)
	if err != nil {
		return nil, err
	}

	// seal with manifest set
	state := sealedState{
		Privk:       x509Encoded,
		RawManifest: c.rawManifest,
		RawCert:     c.cert.Raw,
		State:       c.state,
		Secrets:     c.secrets,
		Activations: c.activations,
	}
	stateRaw, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	return c.sealer.Seal(stateRaw)
}

func (c *Core) generateCert(dnsNames []string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	defer c.mux.Unlock()
	if err := c.requireState(stateUninitialized); err != nil {
		return nil, nil, err
	}

	privk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(math.MaxInt64)

	serialNumber, err := util.GenerateCertificateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	// TODO: what else do we need to set here?
	// Do we need x509.KeyUsageKeyEncipherment?
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: CoordinatorName,
		},
		DNSNames:    dnsNames,
		IPAddresses: util.DefaultCertificateIPAddresses,
		NotBefore:   notBefore,
		NotAfter:    notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, &privk.PublicKey, privk)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return nil, nil, err
	}

	return cert, privk, nil
}

func (c *Core) generateQuote() []byte {
	c.zaplogger.Info("generating quote")
	quote, err := c.qi.Issue(c.cert.Raw)
	if err != nil {
		c.zaplogger.Warn("Failed to get quote. Proceeding in simulation mode.")
		// If we run in SimulationMode we get an error here
		// For testing purpose we do not want to just fail here
		// Instead we store an empty quote that will make it transparent to the client that the integrity of the mesh can not be guaranteed.
		return []byte{}
	}
	return quote
}

func getClientTLSCert(ctx context.Context) *x509.Certificate {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}
	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	// the following check is just for safety (not for security)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return nil
	}
	return tlsInfo.State.PeerCertificates[0]
}

func (c *Core) getStatus(ctx context.Context) (int, string, error) {
	var status string

	switch c.state {
	case stateRecovery:
		status = "Coordinator is in recovery mode. Either upload a key to unseal the saved state, or set a new manifest. For more information on how to proceed, consult the documentation."
	case stateAcceptingManifest:
		status = "Coordinator is ready to accept a manifest."
	case stateAcceptingMarbles:
		status = "Coordinator is running correctly and ready to accept marbles."
	default:
		return -1, "Cannot determine coordinator status.", errors.New("cannot determine coordinator status")
	}

	return int(c.state), status, nil
}

func (c *Core) generateSecrets(ctx context.Context, secrets map[string]Secret, id uuid.UUID) (map[string]Secret, error) {
	// Create a new map so we do not overwrite the entries in the manifest
	newSecrets := make(map[string]Secret)

	// Generate secrets
	for name, secret := range secrets {

		// Skip secrets from wrong context
		if secret.Shared != (id == uuid.Nil) {
			continue
		}

		c.zaplogger.Info("generating secret", zap.String("name", name), zap.String("type", secret.Type), zap.Uint("size", secret.Size))
		switch secret.Type {
		// Raw = Symmetric Key
		case "symmetric-key":
			// Check secret size
			if secret.Size == 0 || secret.Size%8 != 0 {
				return nil, fmt.Errorf("invalid secret size: %v", name)
			}

			var generatedValue []byte
			// If a secret is shared, we generate a completely random key. If a secret is constrained to a marble, we derive a key from the core's private key.
			if secret.Shared {
				generatedValue = make([]byte, secret.Size/8)
				_, err := rand.Read(generatedValue)
				if err != nil {
					return nil, err
				}
			} else {
				salt := id.String() + name
				secretKeyDerive := c.privk.D.Bytes()
				var err error
				generatedValue, err = util.DeriveKey(secretKeyDerive, []byte(salt), secret.Size/8)
				if err != nil {
					return nil, err
				}
			}

			// Get secret object from manifest, create a copy, modify it and put in in the new map so we do not overwrite the manifest entires
			secret.Private = generatedValue
			secret.Public = generatedValue

			newSecrets[name] = secret

		case "cert-rsa":
			// Generate keys
			privKey, err := rsa.GenerateKey(rand.Reader, int(secret.Size))
			if err != nil {
				c.zaplogger.Error("Failed to generate RSA key", zap.Error(err))
				return nil, err
			}

			// Generate certificate
			newSecrets[name], err = c.generateCertificateForSecret(secret, privKey, &privKey.PublicKey)
			if err != nil {
				return nil, err
			}

		case "cert-ed25519":
			if secret.Size != 0 {
				return nil, fmt.Errorf("invalid secret size for cert-ed25519, none is expected. given: %v", name)
			}

			// Generate keys
			pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				c.zaplogger.Error("Failed to generate ed25519 key", zap.Error(err))
				return nil, err
			}

			// Generate certificate
			newSecrets[name], err = c.generateCertificateForSecret(secret, privKey, pubKey)
			if err != nil {
				return nil, err
			}

		case "cert-ecdsa":
			var curve elliptic.Curve

			switch secret.Size {
			case 224:
				curve = elliptic.P224()
			case 256:
				curve = elliptic.P256()
			case 384:
				curve = elliptic.P384()
			case 521:
				curve = elliptic.P521()
			default:
				c.zaplogger.Error("ECDSA secrets only support P224, P256, P384 and P521 as curve. Check the supplied size.", zap.String("name", name), zap.String("type", secret.Type), zap.Uint("size", secret.Size))
				return nil, fmt.Errorf("unsupported size %d: does not map to a supported curve", secret.Size)
			}

			// Generate keys
			privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				c.zaplogger.Error("Failed to generate ECSDA key", zap.Error(err))
				return nil, err
			}

			// Generate certificate
			newSecrets[name], err = c.generateCertificateForSecret(secret, privKey, &privKey.PublicKey)
			if err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("unsupported secret of type %s", secret.Type)
		}
	}

	return newSecrets, nil
}

func (c *Core) generateCertificateForSecret(secret Secret, privKey crypto.PrivateKey, pubKey crypto.PublicKey) (Secret, error) {
	// Load given information from manifest as template
	template := x509.Certificate(secret.Cert)

	// Define or overwrite some values for sane standards
	if template.DNSNames == nil {
		template.DNSNames = []string{"localhost"}
	}
	if template.IPAddresses == nil {
		template.IPAddresses = util.DefaultCertificateIPAddresses
	}
	if template.KeyUsage == 0 {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	}
	if template.ExtKeyUsage == nil {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	if template.Subject.CommonName == "" {
		template.Subject.CommonName = "Marblerun Generated Certificate"
	}
	if template.SerialNumber == nil {
		var err error
		template.SerialNumber, err = util.GenerateCertificateSerialNumber()
		if err != nil {
			c.zaplogger.Error("No serial number supplied; random number generation failed.", zap.Error(err))
			return Secret{}, err
		}
	}

	template.IsCA = false
	template.Issuer = c.cert.Subject
	template.BasicConstraintsValid = true
	template.NotBefore = time.Now()

	// If NotAfter is not set, we will use ValidFor for the end of the certificate lifetime. If it set, we will use it (-> do not adjust it, it's already loaded). If both are set, we will throw an error as this will create ambiguity.
	if template.NotAfter.IsZero() {
		// User can specify a duration in days, otherwise it's one year by default
		if secret.ValidFor == 0 {
			secret.ValidFor = 365
		}

		template.NotAfter = time.Now().AddDate(0, 0, int(secret.ValidFor))
	} else if secret.ValidFor != 0 {
		return Secret{}, errors.New("ambigious certificate validity duration, both NotAfter and ValidFor are specified")
	}

	// Generate certificate with given public key
	secretCertRaw, err := x509.CreateCertificate(rand.Reader, &template, c.cert, pubKey, c.privk)

	if err != nil {
		c.zaplogger.Error("Failed to generate X.509 certificate", zap.Error(err))
		return Secret{}, err
	}

	cert, err := x509.ParseCertificate(secretCertRaw)
	if err != nil {
		c.zaplogger.Error("Failed to parse newly generated X.509 certificate", zap.Error(err))
		return Secret{}, err
	}

	// Assemble secret object
	secret.Cert = Certificate(*cert)
	secret.Private, err = x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		c.zaplogger.Error("Failed to marshal private key to secret object", zap.Error(err))
		return Secret{}, err
	}
	secret.Public, err = x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		c.zaplogger.Error("Failed to marshal public key to secret object", zap.Error(err))
		return Secret{}, err
	}

	return secret, nil
}
