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
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	corecrypto "github.com/edgelesssys/marblerun/coordinator/crypto"
	"github.com/edgelesssys/marblerun/coordinator/events"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper"
	"github.com/edgelesssys/marblerun/util"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// Core implements the core logic of the Coordinator.
type Core struct {
	mux sync.Mutex

	quote []byte
	qv    quote.Validator
	qi    quote.Issuer

	recovery recovery.Recovery
	metrics  *coreMetrics

	txHandle transactionHandle

	log      *zap.Logger
	eventlog *events.Log

	rpc.UnimplementedMarbleServer
}

// RequireState checks if the Coordinator is in one of the given states.
// This function locks the Core's mutex and therefore should be paired with `defer c.mux.Unlock()`.
func (c *Core) RequireState(states ...state.State) error {
	c.mux.Lock()

	getter, rollback, _, err := wrapper.WrapTransaction(c.txHandle)
	if err != nil {
		return err
	}
	defer rollback()

	curState, err := getter.GetState()
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

// AdvanceState advances the state of the Coordinator.
func (c *Core) AdvanceState(newState state.State, tx interface {
	PutState(state.State) error
	GetState() (state.State, error)
},
) error {
	curState, err := tx.GetState()
	if err != nil {
		return err
	}
	if !(curState < newState && newState < state.Max) {
		panic(fmt.Errorf("cannot advance from %d to %d", curState, newState))
	}
	return tx.PutState(newState)
}

// Unlock the Core's mutex.
func (c *Core) Unlock() {
	c.mux.Unlock()
}

// NewCore creates and initializes a new Core object.
func NewCore(dnsNames []string, qv quote.Validator, qi quote.Issuer, stor store.Store, recovery recovery.Recovery, zapLogger *zap.Logger, promFactory *promauto.Factory, eventlog *events.Log) (*Core, error) {
	c := &Core{
		qv:       qv,
		qi:       qi,
		recovery: recovery,
		txHandle: stor,
		log:      zapLogger,
		eventlog: eventlog,
	}
	c.metrics = newCoreMetrics(promFactory, c, "coordinator")

	zapLogger.Info("loading state")
	recoveryData, loadErr := stor.LoadState()
	if err := c.recovery.SetRecoveryData(recoveryData); err != nil {
		c.log.Error("Could not retrieve recovery data from state. Recovery will be unavailable", zap.Error(err))
	}

	transaction, rollback, commit, err := wrapper.WrapTransaction(c.txHandle)
	if err != nil {
		return nil, err
	}
	defer rollback()

	// set core to uninitialized if no state is set
	if _, err := transaction.GetState(); err != nil {
		if errors.Is(err, store.ErrValueUnset) {
			if err := transaction.PutState(state.Uninitialized); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	if loadErr != nil {
		if loadErr != seal.ErrEncryptionKey {
			return nil, loadErr
		}
		// sealed state was found but couldnt be decrypted, go to recovery mode or reset manifest
		c.log.Error("Failed to decrypt sealed state. Processing with a new state. Use the /recover API endpoint to load an old state, or submit a new manifest to overwrite the old state. Look up the documentation for more information on how to proceed.")
		if err := c.setCAData(dnsNames, transaction); err != nil {
			return nil, err
		}
		if err := c.AdvanceState(state.Recovery, transaction); err != nil {
			return nil, err
		}
	} else if _, err := transaction.GetRawManifest(); errors.Is(err, store.ErrValueUnset) {
		// no state was found, wait for manifest
		c.log.Info("No sealed state found. Proceeding with new state.")
		if err := c.setCAData(dnsNames, transaction); err != nil {
			return nil, err
		}
		if err := transaction.PutState(state.AcceptingManifest); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		// recovered from a sealed state, reload components and finish the store transaction
		stor.SetRecoveryData(recoveryData)
	}

	rootCert, err := transaction.GetCertificate(constants.SKCoordinatorRootCert)
	if err != nil {
		return nil, err
	}

	if err := commit(); err != nil {
		return nil, err
	}

	err = c.GenerateQuote(rootCert.Raw)
	return c, err
}

// NewCoreWithMocks creates a new core object with quote and seal mocks for testing.
func NewCoreWithMocks() *Core {
	zapLogger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}

	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	recovery := recovery.NewSinglePartyRecovery()
	core, err := NewCore([]string{"localhost"}, validator, issuer, stdstore.New(sealer), recovery, zapLogger, nil, nil)
	if err != nil {
		panic(err)
	}
	return core
}

// inSimulationMode returns true if we operate in OE_SIMULATION mode.
func (c *Core) inSimulationMode() bool {
	return len(c.quote) == 0
}

// GetTLSConfig gets the core's TLS configuration.
func (c *Core) GetTLSConfig() (*tls.Config, error) {
	return &tls.Config{
		GetCertificate: c.GetTLSRootCertificate,
		ClientAuth:     tls.RequestClientCert,
	}, nil
}

// GetTLSRootCertificate creates a TLS certificate for the Coordinators self-signed x509 certificate.
//
// This function initializes a read transaction and should not be called from other functions with ongoing transactions.
func (c *Core) GetTLSRootCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	data, rollback, _, err := wrapper.WrapTransaction(c.txHandle)
	if err != nil {
		return nil, err
	}
	defer rollback()

	curState, err := data.GetState()
	if err != nil {
		return nil, err
	}
	if curState == state.Uninitialized {
		return nil, errors.New("don't have a cert yet")
	}

	rootCert, err := data.GetCertificate(constants.SKCoordinatorRootCert)
	if err != nil {
		return nil, err
	}
	rootPrivK, err := data.GetPrivateKey(constants.SKCoordinatorRootKey)
	if err != nil {
		return nil, err
	}

	return util.TLSCertFromDER(rootCert.Raw, rootPrivK), nil
}

// GetTLSMarbleRootCertificate creates a TLS certificate for the Coordinator's x509 marbleRoot certificate.
//
// This function initializes a read transaction and should not be called from other functions with ongoing transactions.
func (c *Core) GetTLSMarbleRootCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	data, rollback, _, err := wrapper.WrapTransaction(c.txHandle)
	if err != nil {
		return nil, err
	}
	defer rollback()

	curState, err := data.GetState()
	if err != nil {
		return nil, err
	}
	if curState == state.Uninitialized {
		return nil, errors.New("don't have a cert yet")
	}

	marbleRootCert, err := data.GetCertificate(constants.SKMarbleRootCert)
	if err != nil {
		return nil, err
	}
	intermediatePrivK, err := data.GetPrivateKey(constants.SKCoordinatorIntermediateKey)
	if err != nil {
		return nil, err
	}

	return util.TLSCertFromDER(marbleRootCert.Raw, intermediatePrivK), nil
}

// GetQuote returns the quote of the Coordinator.
func (c *Core) GetQuote() []byte {
	return c.quote
}

// GenerateQuote generates a quote for the Coordinator using the given certificate.
// If no quote can be generated due to the system not supporting SGX, no error is returned,
// and the Coordinator proceeds to run in simulation mode.
func (c *Core) GenerateQuote(cert []byte) error {
	c.log.Info("generating quote")
	quote, err := c.qi.Issue(cert)
	if err != nil {
		if err.Error() == "OE_UNSUPPORTED" {
			c.log.Warn("Failed to get quote. Proceeding in simulation mode.", zap.Error(err))
			// If we run in SimulationMode we get OE_UNSUPPORTED error here
			// For testing purpose we do not want to just fail here
			// Instead we store an empty quote that will make it transparent to the client that the integrity of the mesh can not be guaranteed.
			return nil
		}
		return QuoteError{err}
	}

	c.quote = quote

	return nil
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

// GetState returns the current state of the Coordinator.
func (c *Core) GetState() (state.State, string, error) {
	data, rollback, _, err := wrapper.WrapTransaction(c.txHandle)
	if err != nil {
		return -1, "Cannot determine coordinator status.", fmt.Errorf("initializing read transaction: %w", err)
	}
	defer rollback()

	curState, err := data.GetState()
	if err != nil {
		return -1, "Cannot determine coordinator status.", err
	}

	var status string

	switch curState {
	case state.Recovery:
		status = "Coordinator is in recovery mode. Either upload a key to unseal the saved state, or set a new manifest. For more information on how to proceed, consult the documentation."
	case state.AcceptingManifest:
		status = "Coordinator is ready to accept a manifest."
	case state.AcceptingMarbles:
		status = "Coordinator is running correctly and ready to accept marbles."
	default:
		return -1, "Cannot determine coordinator status.", errors.New("cannot determine coordinator status")
	}

	return curState, status, nil
}

// GenerateSecrets generates secrets for the given manifest and parent certificate.
func (c *Core) GenerateSecrets(
	secrets map[string]manifest.Secret, id uuid.UUID,
	parentCertificate *x509.Certificate, parentPrivKey *ecdsa.PrivateKey, rootPrivK *ecdsa.PrivateKey,
) (map[string]manifest.Secret, error) {
	// Create a new map so we do not overwrite the entries in the manifest
	newSecrets := make(map[string]manifest.Secret)

	// Generate secrets
	for name, secret := range secrets {
		// Skip user defined secrets, these will be uploaded by a user
		if secret.UserDefined {
			continue
		}

		// Skip secrets from wrong context
		if secret.Shared != (id == uuid.Nil) {
			continue
		}

		c.log.Info("generating secret", zap.String("name", name), zap.String("type", secret.Type), zap.Uint("size", secret.Size))
		switch secret.Type {
		// Raw = Symmetric Key
		case manifest.SecretTypeSymmetricKey:
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

			// Get secret object from manifest, create a copy, modify it and put in in the new map so we do not overwrite the manifest entries
			secret.Private = generatedValue
			secret.Public = generatedValue

			newSecrets[name] = secret

		case manifest.SecretTypeCertRSA:
			// Generate keys
			privKey, err := rsa.GenerateKey(rand.Reader, int(secret.Size))
			if err != nil {
				c.log.Error("Failed to generate RSA key", zap.Error(err))
				return nil, err
			}

			// Generate certificate
			newSecrets[name], err = c.generateCertificateForSecret(secret, parentCertificate, parentPrivKey, privKey, &privKey.PublicKey)
			if err != nil {
				return nil, err
			}

		case manifest.SecretTypeCertED25519:
			if secret.Size != 0 {
				return nil, fmt.Errorf("invalid secret size for cert-ed25519, none is expected. given: %v", name)
			}

			// Generate keys
			pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				c.log.Error("Failed to generate ed25519 key", zap.Error(err))
				return nil, err
			}

			// Generate certificate
			newSecrets[name], err = c.generateCertificateForSecret(secret, parentCertificate, parentPrivKey, privKey, pubKey)
			if err != nil {
				return nil, err
			}

		case manifest.SecretTypeCertECDSA:
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
				c.log.Error("ECDSA secrets only support P224, P256, P384 and P521 as curve. Check the supplied size.", zap.String("name", name), zap.String("type", secret.Type), zap.Uint("size", secret.Size))
				return nil, fmt.Errorf("unsupported size %d: does not map to a supported curve", secret.Size)
			}

			// Generate keys
			privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				c.log.Error("Failed to generate ECSDA key", zap.Error(err))
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
		if len(template.DNSNames) == 1 {
			template.Subject.CommonName = template.DNSNames[0]
		} else {
			template.Subject.CommonName = "MarbleRun Generated Certificate"
		}
	}
	var err error
	template.SerialNumber, err = util.GenerateCertificateSerialNumber()
	if err != nil {
		c.log.Error("No serial number supplied; random number generation failed.", zap.Error(err))
		return manifest.Secret{}, err
	}

	template.BasicConstraintsValid = true
	template.NotBefore = time.Now()

	// If NotAfter is not set, we will use ValidFor for the end of the certificate lifetime. This can only happen once on initial manifest set
	if template.NotAfter.IsZero() {
		// User can specify a duration in days, otherwise it's one year by default
		if secret.ValidFor == 0 {
			secret.ValidFor = 365
		}

		template.NotAfter = time.Now().AddDate(0, 0, int(secret.ValidFor))
	} else if secret.ValidFor != 0 {
		// reset expiration date for private secrets
		if !secret.Shared {
			template.NotAfter = time.Now().AddDate(0, 0, int(secret.ValidFor))
		}
	}

	// Generate certificate with given public key
	secretCertRaw, err := x509.CreateCertificate(rand.Reader, &template, parentCertificate, pubKey, parentPrivKey)
	if err != nil {
		c.log.Error("Failed to generate X.509 certificate", zap.Error(err))
		return manifest.Secret{}, err
	}

	cert, err := x509.ParseCertificate(secretCertRaw)
	if err != nil {
		c.log.Error("Failed to parse newly generated X.509 certificate", zap.Error(err))
		return manifest.Secret{}, err
	}

	// Assemble secret object
	secret.Cert = manifest.Certificate(*cert)
	secret.Private, err = x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		c.log.Error("Failed to marshal private key to secret object", zap.Error(err))
		return manifest.Secret{}, err
	}
	secret.Public, err = x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		c.log.Error("Failed to marshal public key to secret object", zap.Error(err))
		return manifest.Secret{}, err
	}

	return secret, nil
}

func (c *Core) setCAData(dnsNames []string, putter interface {
	PutCertificate(name string, cert *x509.Certificate) error
	PutPrivateKey(name string, key *ecdsa.PrivateKey) error
},
) error {
	rootCert, rootPrivK, err := corecrypto.GenerateCert(dnsNames, constants.CoordinatorName, nil, nil, nil)
	if err != nil {
		return err
	}
	// Creating a cross-signed intermediate cert. See https://github.com/edgelesssys/marblerun/issues/175
	intermediateCert, intermediatePrivK, err := corecrypto.GenerateCert(dnsNames, constants.CoordinatorIntermediateName, nil, rootCert, rootPrivK)
	if err != nil {
		return err
	}
	marbleRootCert, _, err := corecrypto.GenerateCert(dnsNames, constants.CoordinatorIntermediateName, intermediatePrivK, nil, nil)
	if err != nil {
		return err
	}

	if err := putter.PutCertificate(constants.SKCoordinatorRootCert, rootCert); err != nil {
		return err
	}
	if err := putter.PutCertificate(constants.SKCoordinatorIntermediateCert, intermediateCert); err != nil {
		return err
	}
	if err := putter.PutCertificate(constants.SKMarbleRootCert, marbleRootCert); err != nil {
		return err
	}
	if err := putter.PutPrivateKey(constants.SKCoordinatorRootKey, rootPrivK); err != nil {
		return err
	}
	if err := putter.PutPrivateKey(constants.SKCoordinatorIntermediateKey, intermediatePrivK); err != nil {
		return err
	}

	return nil
}

// QuoteError is returned when the quote could not be retrieved.
type QuoteError struct {
	err error
}

// Error returns the error message.
func (e QuoteError) Error() string {
	return fmt.Sprintf("failed to get quote: %v", e.err)
}

type transactionHandle interface {
	BeginTransaction() (store.Transaction, error)
}
