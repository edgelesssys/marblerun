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
	"strings"
	"sync"
	"time"

	"github.com/edgelesssys/marblerun/coordinator/events"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/updatelog"
	"github.com/edgelesssys/marblerun/coordinator/user"
	"github.com/edgelesssys/marblerun/util"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// Core implements the core logic of the Coordinator.
type Core struct {
	mux          sync.Mutex
	quote        []byte
	recovery     recovery.Recovery
	store        store.Store
	data         storeWrapper
	sealer       seal.Sealer
	qv           quote.Validator
	qi           quote.Issuer
	updateLogger *updatelog.Logger
	zaplogger    *zap.Logger
	metrics      *coreMetrics
	eventlog     *events.Log
	rpc.UnimplementedMarbleServer
}

// The sequence of states a Coordinator may be in.
type state int

const (
	stateUninitialized state = iota
	stateRecovery
	stateAcceptingManifest
	stateAcceptingMarbles
	stateMax
)

// coordinatorName is the name of the Coordinator. It is used as CN of the root certificate.
const coordinatorName string = "MarbleRun Coordinator"

// coordinatorIntermediateName is the name of the Coordinator. It is used as CN of the intermediate certificate which is set when setting or updating a certificate.
const coordinatorIntermediateName string = "MarbleRun Coordinator - Intermediate CA"

// storage keys for the used in the Coordinator.
const (
	sKCoordinatorRootCert         string = "coordinatorRootCert"
	sKCoordinatorRootKey          string = "coordinatorRootKey"
	skCoordinatorIntermediateCert string = "coordinatorIntermediateCert"
	sKMarbleRootCert              string = "marbleRootCert"
	sKCoordinatorIntermediateKey  string = "coordinatorIntermediateKey"
)

// Needs to be paired with `defer c.mux.Unlock()`.
func (c *Core) requireState(states ...state) error {
	c.mux.Lock()
	curState, err := c.data.getState()
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

func (c *Core) advanceState(newState state, tx store.Transaction) error {
	txdata := storeWrapper{tx}
	curState, err := txdata.getState()
	if err != nil {
		return err
	}
	if !(curState < newState && newState < stateMax) {
		panic(fmt.Errorf("cannot advance from %d to %d", curState, newState))
	}
	return txdata.putState(newState)
}

// NewCore creates and initializes a new Core object.
func NewCore(dnsNames []string, qv quote.Validator, qi quote.Issuer, sealer seal.Sealer, recovery recovery.Recovery, zapLogger *zap.Logger, promFactory *promauto.Factory, eventlog *events.Log) (*Core, error) {
	stor := store.NewStdStore(sealer)
	c := &Core{
		qv:        qv,
		qi:        qi,
		recovery:  recovery,
		store:     stor,
		data:      storeWrapper{store: stor},
		sealer:    sealer,
		zaplogger: zapLogger,
		eventlog:  eventlog,
	}
	c.metrics = newCoreMetrics(promFactory, c, "coordinator")

	var err error
	c.updateLogger, err = updatelog.New()
	if err != nil {
		return nil, err
	}

	zapLogger.Info("loading state")
	recoveryData, loadErr := stor.LoadState()
	if err := c.recovery.SetRecoveryData(recoveryData); err != nil {
		c.zaplogger.Error("Could not retrieve recovery data from state. Recovery will be unavailable", zap.Error(err))
	}

	tx, err := c.store.BeginTransaction()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	txdata := storeWrapper{tx}

	// set core to uninitialized if no state is set
	if _, err := txdata.getState(); err != nil {
		if store.IsStoreValueUnsetError(err) {
			if err := txdata.putState(stateUninitialized); err != nil {
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
		c.zaplogger.Error("Failed to decrypt sealed state. Processing with a new state. Use the /recover API endpoint to load an old state, or submit a new manifest to overwrite the old state. Look up the documentation for more information on how to proceed.")
		if err := c.setCAData(dnsNames, tx); err != nil {
			return nil, err
		}
		if err := c.advanceState(stateRecovery, tx); err != nil {
			return nil, err
		}
	} else if _, err := txdata.getRawManifest(); store.IsStoreValueUnsetError(err) {
		// no state was found, wait for manifest
		c.zaplogger.Info("No sealed state found. Proceeding with new state.")
		if err := c.setCAData(dnsNames, tx); err != nil {
			return nil, err
		}
		if err := txdata.putState(stateAcceptingManifest); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		// recovered from a sealed state, reload components and finish the store transaction
		stor.SetRecoveryData(recoveryData)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	rootCert, err := c.data.getCertificate(sKCoordinatorRootCert)
	if err != nil {
		return nil, err
	}
	c.quote, err = c.generateQuote(rootCert.Raw)

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
	core, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger, nil, nil)
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
func (c *Core) GetTLSRootCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	curState, err := c.data.getState()
	if err != nil {
		return nil, err
	}
	if curState == stateUninitialized {
		return nil, errors.New("don't have a cert yet")
	}

	rootCert, err := c.data.getCertificate(sKCoordinatorRootCert)
	if err != nil {
		return nil, err
	}
	rootPrivK, err := c.data.getPrivK(sKCoordinatorRootKey)
	if err != nil {
		return nil, err
	}

	return util.TLSCertFromDER(rootCert.Raw, rootPrivK), nil
}

// GetTLSMarbleRootCertificate creates a TLS certificate for the Coordinator's x509 marbleRoot certificate.
func (c *Core) GetTLSMarbleRootCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	curState, err := c.data.getState()
	if err != nil {
		return nil, err
	}
	if curState == stateUninitialized {
		return nil, errors.New("don't have a cert yet")
	}

	marbleRootCert, err := c.data.getCertificate(sKMarbleRootCert)
	if err != nil {
		return nil, err
	}
	intermediatePrivK, err := c.data.getPrivK(sKCoordinatorIntermediateKey)
	if err != nil {
		return nil, err
	}

	return util.TLSCertFromDER(marbleRootCert.Raw, intermediatePrivK), nil
}

func generateCert(dnsNames []string, commonName string, privk *ecdsa.PrivateKey, parentCertificate *x509.Certificate, parentPrivateKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// Generate private key
	var err error
	if privk == nil {
		privk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
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

func (c *Core) generateQuote(cert []byte) ([]byte, error) {
	c.zaplogger.Info("generating quote")
	quote, err := c.qi.Issue(cert)
	if err != nil {
		if err.Error() == "OE_UNSUPPORTED" {
			c.zaplogger.Warn("Failed to get quote. Proceeding in simulation mode.", zap.Error(err))
			// If we run in SimulationMode we get OE_UNSUPPORTED error here
			// For testing purpose we do not want to just fail here
			// Instead we store an empty quote that will make it transparent to the client that the integrity of the mesh can not be guaranteed.
			return []byte{}, nil
		}
		return nil, QuoteError{err}
	}
	return quote, nil
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
	curState, err := c.data.getState()
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

	rootPrivK, err := c.data.getPrivK(sKCoordinatorRootKey)
	if err != nil {
		return nil, err
	}

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

			// Get secret object from manifest, create a copy, modify it and put in in the new map so we do not overwrite the manifest entries
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
		if len(template.DNSNames) == 1 {
			template.Subject.CommonName = template.DNSNames[0]
		} else {
			template.Subject.CommonName = "MarbleRun Generated Certificate"
		}
	}
	var err error
	template.SerialNumber, err = util.GenerateCertificateSerialNumber()
	if err != nil {
		c.zaplogger.Error("No serial number supplied; random number generation failed.", zap.Error(err))
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

// generateUsersFromManifest creates users and permissions from a map of manifest.User.
func generateUsersFromManifest(rawUsers map[string]manifest.User, roles map[string]manifest.Role) ([]*user.User, error) {
	// Parse & write X.509 user data from manifest
	users := make([]*user.User, 0, len(rawUsers))
	for name, userData := range rawUsers {
		block, _ := pem.Decode([]byte(userData.Certificate))
		if block == nil {
			return nil, fmt.Errorf("received invalid certificate for user %s", name)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		newUser := user.NewUser(name, cert)
		for _, assignedRole := range userData.Roles {
			for _, action := range roles[assignedRole].Actions {
				// correctness of roles has been verified by manifest.Check()
				newUser.Assign(user.NewPermission(strings.ToLower(action), roles[assignedRole].ResourceNames))
			}
		}
		users = append(users, newUser)
	}
	return users, nil
}

func (c *Core) setCAData(dnsNames []string, tx store.Transaction) error {
	rootCert, rootPrivK, err := generateCert(dnsNames, coordinatorName, nil, nil, nil)
	if err != nil {
		return err
	}
	// Creating a cross-signed intermediate cert. See https://github.com/edgelesssys/marblerun/issues/175
	intermediateCert, intermediatePrivK, err := generateCert(dnsNames, coordinatorIntermediateName, nil, rootCert, rootPrivK)
	if err != nil {
		return err
	}
	marbleRootCert, _, err := generateCert(dnsNames, coordinatorIntermediateName, intermediatePrivK, nil, nil)
	if err != nil {
		return err
	}

	txdata := storeWrapper{tx}
	if err := txdata.putCertificate(sKCoordinatorRootCert, rootCert); err != nil {
		return err
	}
	if err := txdata.putCertificate(skCoordinatorIntermediateCert, intermediateCert); err != nil {
		return err
	}
	if err := txdata.putCertificate(sKMarbleRootCert, marbleRootCert); err != nil {
		return err
	}
	if err := txdata.putPrivK(sKCoordinatorRootKey, rootPrivK); err != nil {
		return err
	}
	if err := txdata.putPrivK(sKCoordinatorIntermediateKey, intermediatePrivK); err != nil {
		return err
	}

	return nil
}

type QuoteError struct {
	err error
}

func (e QuoteError) Error() string {
	return fmt.Sprintf("failed to get quote: %v", e.err)
}
