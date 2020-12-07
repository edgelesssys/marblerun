// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package core provides the core functionality for the Coordinator object including state transition, APIs for marbles and clients, handling of manifests and the sealing functionalities.
package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/util"
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

	// Decode secret certificates from PEM
	for name, secret := range loadedState.Secrets {
		secretObject := loadedState.Secrets[name]
		certPem := secret.CertEncoded

		if certPem != "" {
			block, _ := pem.Decode([]byte(certPem))
			if block == nil {
				c.zaplogger.Error("Could not decode certificate PEM from secret", zap.String("name", name))
				return nil, nil, errors.New("failed to parse certificate PEM")
			}
			parsedCertificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			secretObject.Cert = parsedCertificate
			loadedState.Secrets[name] = secretObject
		}
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

	// Encode secret certificates to PEM to avoid JSON unmarshal errors due to BigInt
	for name, secret := range c.secrets {
		secretObject := c.secrets[name]
		cert := secret.Cert

		if cert != nil {
			pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
			secretObject.CertEncoded = string(pemData)
			secretObject.Cert = nil
			c.secrets[name] = secretObject
		}
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
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
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

func (c *Core) generateSecrets(ctx context.Context, secrets map[string]Secret) (map[string]Secret, error) {
	// Create a new map so we do not overwrite the entries in the manifest
	newSecrets := make(map[string]Secret)

	// Generate secrets
	for name, secret := range secrets {
		// Check secret size
		if secret.Size == 0 || secret.Size%8 != 0 {
			return nil, fmt.Errorf("invalid secret size: %v", name)
		}

		switch secret.Type {
		// Raw = Symmetric Key
		case "raw":
			c.zaplogger.Info("generating raw secret", zap.String("name", name), zap.String("type", secret.Type), zap.Uint("size", secret.Size))

			generatedValue := make([]byte, secret.Size/8)
			_, err := rand.Read(generatedValue)
			if err != nil {
				return nil, err
			}

			// Get secret object from manifest, create a copy, modify it and put in in the new map so we do not overwrite the manifest entires
			filledSecret := secrets[name]
			filledSecret.Private = generatedValue
			filledSecret.Public = generatedValue

			newSecrets[name] = filledSecret

		case "cert-rsa":
			c.zaplogger.Info("generating RSA certificate as secret", zap.String("name", name), zap.String("type", secret.Type), zap.Uint("size", secret.Size))

			filledSecret := secrets[name]

			// Generate keys
			privKey, err := rsa.GenerateKey(rand.Reader, int(secret.Size))
			if err != nil {
				c.zaplogger.Error("Failed to generate RSA key", zap.Error(err))
				return nil, err
			}
			filledSecret.Private, err = x509.MarshalPKCS8PrivateKey(privKey)
			if err != nil {
				c.zaplogger.Error("Failed to marshal RSA private key to secret object", zap.Error(err))
				return nil, err
			}
			filledSecret.Public, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			if err != nil {
				c.zaplogger.Error("Failed to marshal RSA public key to secret object", zap.Error(err))
				return nil, err
			}

			// Generate certificate
			filledSecret.Cert, err = c.generateCertificateForSecret(secret, privKey.PublicKey)
			if err != nil {
				return nil, err
			}

			// Write to map
			newSecrets[name] = filledSecret

		case "cert-ed25519":
			c.zaplogger.Info("generating Ed25519 certificate as secret", zap.String("name", name), zap.String("type", secret.Type), zap.Uint("size", secret.Size))

			if secret.Size != 256 {
				return nil, fmt.Errorf("ed25519 needs to specify size 256. supplied: %d", secret.Size)
			}

			filledSecret := secrets[name]

			// Generate keys
			pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				c.zaplogger.Error("Failed to generate ed25519 key", zap.Error(err))
				return nil, err
			}
			filledSecret.Private, err = x509.MarshalPKCS8PrivateKey(privKey)
			if err != nil {
				c.zaplogger.Error("Failed to marshal ed25519 private key to secret object", zap.Error(err))
				return nil, err
			}
			filledSecret.Public, err = x509.MarshalPKIXPublicKey(pubKey)
			if err != nil {
				c.zaplogger.Error("Failed to marshal ed25519 public key to secret object", zap.Error(err))
				return nil, err
			}

			// Generate certificate
			filledSecret.Cert, err = c.generateCertificateForSecret(secret, pubKey)
			if err != nil {
				return nil, err
			}

			// Write to map
			newSecrets[name] = filledSecret

		case "cert-ecdsa":
			c.zaplogger.Info("generating ECDSA certificate as secret", zap.String("name", name), zap.String("type", secret.Type), zap.Uint("size", secret.Size))

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

			filledSecret := secrets[name]

			// Generate keys
			privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				c.zaplogger.Error("Failed to generate ECSDA key", zap.Error(err))
				return nil, err
			}
			filledSecret.Private, err = x509.MarshalPKCS8PrivateKey(privKey)
			if err != nil {
				c.zaplogger.Error("Failed to marshal ECDSA private key to secret object", zap.Error(err))
				return nil, err
			}
			filledSecret.Public, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			if err != nil {
				c.zaplogger.Error("Failed to marshal ECDSA public key to secret object", zap.Error(err))
				return nil, err
			}

			// Generate certificate
			filledSecret.Cert, err = c.generateCertificateForSecret(secret, privKey.PublicKey)
			if err != nil {
				return nil, err
			}

			// Write to map
			newSecrets[name] = filledSecret

		// Everything else so far is not supported
		default:
			return nil, fmt.Errorf("unsupported secret of type %s", secret.Type)
		}
	}

	return newSecrets, nil
}

func (c *Core) generateCertificateForSecret(secret Secret, key interface{}) (*x509.Certificate, error) {
	// Load given information from manifest as template
	template := secret.Cert

	// Define or overwrite some values for sane standards
	if template.DNSNames == nil {
		template.DNSNames = c.cert.DNSNames
	}
	if template.IPAddresses == nil {
		template.IPAddresses = c.cert.IPAddresses
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

	template.IsCA = false
	template.Issuer = c.cert.Subject
	template.BasicConstraintsValid = true
	template.NotBefore = time.Now()

	// User can specify a duration in days, otherwise it's one year by default
	if secret.ValidFor != 0 {
		template.NotAfter = time.Now().Add(time.Hour * 24 * time.Duration(secret.ValidFor))
	} else {
		template.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	}

	// Generate certificate with given public key
	var secretCertRaw []byte
	var err error

	// We have to use a switch case here to define the type of the key
	// Also, ed25519 adresses the key differently
	switch keyWithType := key.(type) {
	case rsa.PublicKey:
		secretCertRaw, err = x509.CreateCertificate(rand.Reader, template, c.cert, &keyWithType, c.privk)
	case ed25519.PublicKey:
		secretCertRaw, err = x509.CreateCertificate(rand.Reader, template, c.cert, keyWithType, c.privk)
	case ecdsa.PublicKey:
		secretCertRaw, err = x509.CreateCertificate(rand.Reader, template, c.cert, &keyWithType, c.privk)
	default:
		return nil, fmt.Errorf("unsupported key format: %T", key)
	}

	if err != nil {
		c.zaplogger.Error("Failed to generate X.509 certificate", zap.Error(err))
		return nil, err
	}

	cert, err := x509.ParseCertificate(secretCertRaw)
	if err != nil {
		c.zaplogger.Error("Failed to parse newly generated X.509 certificate", zap.Error(err))
		return nil, err
	}

	return cert, nil
}
