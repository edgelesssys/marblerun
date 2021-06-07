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
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/util"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// Core implements the core logic of the Coordinator
type Core struct {
	quote          []byte
	recovery       recovery.Recovery
	manifest       manifest.Manifest
	updateManifest manifest.Manifest
	store          *storeWrapper
	qv             quote.Validator
	qi             quote.Issuer
	mux            sync.Mutex
	zaplogger      *zap.Logger
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

// marblerunUser represents a privileged user of Marblerun
type marblerunUser struct {
	// name is the username
	name string
	// certificate is the users certificate, used for authentication
	certificate *x509.Certificate
}

// coordinatorName is the name of the Coordinator. It is used as CN of the root certificate.
const coordinatorName string = "Marblerun Coordinator"

// coordinatorIntermediateName is the name of the Coordinator. It is used as CN of the intermediate certificate which is set when setting or updating a certificate.
const coordinatorIntermediateName string = "Marblerun Coordinator - Intermediate CA"

// Needs to be paired with `defer c.mux.Unlock()`
func (c *Core) requireState(states ...state) error {
	c.mux.Lock()
	curState, err := c.store.getState()
	if err != nil {
		return err
	}
	for _, s := range states {
		if s == curState {
			return nil
		}
	}
	return errors.New("server is not in expected state")
}

func (c *Core) advanceState(newState state) error {
	curState, err := c.store.getState()
	if err != nil {
		return err
	}
	if !(curState < newState && newState < stateMax) {
		panic(fmt.Errorf("cannot advance from %d to %d", curState, newState))
	}
	return c.store.putState(newState)
}

// NewCore creates and initializes a new Core object
func NewCore(dnsNames []string, qv quote.Validator, qi quote.Issuer, sealer Sealer, recovery recovery.Recovery, zapLogger *zap.Logger) (*Core, error) {
	c := &Core{
		qv:        qv,
		qi:        qi,
		recovery:  recovery,
		store:     &storeWrapper{store: NewStdStore(sealer, zapLogger)},
		zaplogger: zapLogger,
	}

	if err := c.store.putState(stateUninitialized); err != nil {
		return nil, err
	}

	zapLogger.Info("loading state")
	recoveryData, manifest, updateManifest, loadErr := c.store.loadState()
	if err := c.recovery.SetRecoveryData(recoveryData); err != nil {
		c.zaplogger.Error("Could not retrieve recovery data from state. Recovery will be unavailable", zap.Error(err))
	}

	if loadErr != nil {
		if loadErr != ErrEncryptionKey {
			return nil, loadErr
		}
		// sealed state was found but couldnt be decrypted, go to recovery mode or reset manifest
		c.zaplogger.Error("Failed to decrypt sealed state. Processing with a new state. Use the /recover API endpoint to load an old state, or submit a new manifest to overwrite the old state. Look up the documentation for more information on how to proceed.")
		if err := c.setCAData(dnsNames); err != nil {
			return nil, err
		}
		if err := c.advanceState(stateRecovery); err != nil {
			return nil, err
		}
	} else if _, err := c.store.getCertificate("root"); isStoreValueUnsetError(err) {
		// no state was found, wait for manifest
		c.zaplogger.Info("No sealed state found. Proceeding with new state.")
		if err := c.setCAData(dnsNames); err != nil {
			return nil, err
		}
		if err := c.advanceState(stateAcceptingManifest); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	if manifest != nil {
		c.manifest = *manifest
	}
	if updateManifest != nil {
		c.updateManifest = *updateManifest
	}
	rootCert, err := c.store.getCertificate("root")
	if err != nil {
		return nil, err
	}
	c.quote = c.generateQuote(rootCert.Raw)

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
	recovery := recovery.NewSinglePartyRecovery()
	core, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger)
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
		GetCertificate: c.GetTLSRootCertificate,
		ClientAuth:     tls.RequestClientCert,
	}, nil
}

// GetTLSRootCertificate creates a TLS certificate for the Coordinators self-signed x509 certificate
func (c *Core) GetTLSRootCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	curState, err := c.store.getState()
	if err != nil {
		return nil, err
	}
	if curState == stateUninitialized {
		return nil, errors.New("don't have a cert yet")
	}

	rootCert, err := c.store.getCertificate("root")
	if err != nil {
		return nil, err
	}
	rootPrivK, err := c.store.getPrivK("root")
	if err != nil {
		return nil, err
	}

	return util.TLSCertFromDER(rootCert.Raw, rootPrivK), nil
}

// GetTLSIntermediateCertificate creates a TLS certificate for the Coordinator's x509 intermediate certificate based on the self-signed x509 root certificate
func (c *Core) GetTLSIntermediateCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	curState, err := c.store.getState()
	if err != nil {
		return nil, err
	}
	if curState == stateUninitialized {
		return nil, errors.New("don't have a cert yet")
	}

	intermediateCert, err := c.store.getCertificate("intermediate")
	if err != nil {
		return nil, err
	}
	intermediatePrivK, err := c.store.getPrivK("intermediate")
	if err != nil {
		return nil, err
	}

	return util.TLSCertFromDER(intermediateCert.Raw, intermediatePrivK), nil
}

func generateCert(dnsNames []string, commonName string, parentCertificate *x509.Certificate, parentPrivateKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// Generate private key
	privk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Certifcate parameter
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
			CommonName: commonName,
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

	if parentCertificate == nil {
		parentCertificate = &template
		parentPrivateKey = privk
	}
	certRaw, err := x509.CreateCertificate(rand.Reader, &template, parentCertificate, &privk.PublicKey, parentPrivateKey)

	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return nil, nil, err
	}

	return cert, privk, nil
}

func (c *Core) generateQuote(cert []byte) []byte {
	c.zaplogger.Info("generating quote")
	quote, err := c.qi.Issue(cert)
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
	curState, err := c.store.getState()
	if err != nil {
		return -1, "Cannot determine coordinator status.", err
	}

	var status string

	switch curState {
	case stateRecovery:
		status = "Coordinator is in recovery mode. Either upload a key to unseal the saved state, or set a new manifest. For more information on how to proceed, consult the documentation."
	case stateAcceptingManifest:
		status = "Coordinator is ready to accept a manifest."
	case stateAcceptingMarbles:
		status = "Coordinator is running correctly and ready to accept marbles."
	default:
		return -1, "Cannot determine coordinator status.", errors.New("cannot determine coordinator status")
	}

	return int(curState), status, nil
}

func (c *Core) generateSecrets(ctx context.Context, secrets map[string]manifest.Secret, id uuid.UUID, parentCertificate *x509.Certificate, parentPrivKey *ecdsa.PrivateKey) (map[string]manifest.Secret, error) {
	// Create a new map so we do not overwrite the entries in the manifest
	newSecrets := make(map[string]manifest.Secret)

	rootPrivK, err := c.store.getPrivK("root")
	if err != nil {
		return nil, err
	}

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
				secretKeyDerive := rootPrivK.D.Bytes()
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
			newSecrets[name], err = c.generateCertificateForSecret(secret, parentCertificate, parentPrivKey, privKey, &privKey.PublicKey)
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
			newSecrets[name], err = c.generateCertificateForSecret(secret, parentCertificate, parentPrivKey, privKey, pubKey)
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
			newSecrets[name], err = c.generateCertificateForSecret(secret, parentCertificate, parentPrivKey, privKey, &privKey.PublicKey)
			if err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("unsupported secret of type %s", secret.Type)
		}
	}

	return newSecrets, nil
}

func (c *Core) generateCertificateForSecret(secret manifest.Secret, parentCertificate *x509.Certificate, parentPrivKey *ecdsa.PrivateKey, privKey crypto.PrivateKey, pubKey crypto.PublicKey) (manifest.Secret, error) {
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
			return manifest.Secret{}, err
		}
	}

	template.IsCA = false
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
		return manifest.Secret{}, errors.New("ambigious certificate validity duration, both NotAfter and ValidFor are specified")
	}

	// Generate certificate with given public key
	secretCertRaw, err := x509.CreateCertificate(rand.Reader, &template, parentCertificate, pubKey, parentPrivKey)

	if err != nil {
		c.zaplogger.Error("Failed to generate X.509 certificate", zap.Error(err))
		return manifest.Secret{}, err
	}

	cert, err := x509.ParseCertificate(secretCertRaw)
	if err != nil {
		c.zaplogger.Error("Failed to parse newly generated X.509 certificate", zap.Error(err))
		return manifest.Secret{}, err
	}

	// Assemble secret object
	secret.Cert = manifest.Certificate(*cert)
	secret.Private, err = x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		c.zaplogger.Error("Failed to marshal private key to secret object", zap.Error(err))
		return manifest.Secret{}, err
	}
	secret.Public, err = x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		c.zaplogger.Error("Failed to marshal public key to secret object", zap.Error(err))
		return manifest.Secret{}, err
	}

	return secret, nil
}

func (c *Core) setCAData(dnsNames []string) error {
	rootCert, rootPrivK, err := generateCert(dnsNames, coordinatorName, nil, nil)
	if err != nil {
		return err
	}
	intermediateCert, intermediatePrivK, err := generateCert(dnsNames, coordinatorIntermediateName, rootCert, rootPrivK)
	if err != nil {
		return err
	}
	if err := c.store.putCertificate("root", rootCert); err != nil {
		return err
	}
	if err := c.store.putCertificate("intermediate", intermediateCert); err != nil {
		return err
	}
	if err := c.store.putPrivK("root", rootPrivK); err != nil {
		return err
	}
	if err := c.store.putPrivK("intermediate", intermediatePrivK); err != nil {
		return err
	}

	return nil
}

func generateUsersFromManifest(users map[string]string) ([]*marblerunUser, error) {
	// Parse & write X.509 admin certificates from sealed state
	userData := make([]*marblerunUser, 0, len(users))
	for userName, value := range users {
		block, _ := pem.Decode([]byte(value))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		userData = append(userData, &marblerunUser{name: userName, certificate: cert})
	}

	return userData, nil
}
