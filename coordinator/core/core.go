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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
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
	stateRecovery state = iota - 1
	stateUninitialized
	stateAcceptingManifest
	stateAcceptingMarbles
)

// sealedState represents the state information, required for persistence, that gets sealed to the filesystem
type sealedState struct {
	Privk       []byte
	RawManifest []byte
	RawCert     []byte
	State       state
	Activations map[string]uint
}

// CoordinatorName is the name of the Coordinator. It is used as CN of the root certificate.
const CoordinatorName string = "Marblerun Coordinator"

// Needs to be paired with `defer c.mux.Unlock()`
func (c *Core) requireState(state state) error {
	c.mux.Lock()
	if c.state != state {
		return errors.New("server is not in expected state")
	}
	return nil
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
	cert, privk, err := c.loadState(dnsNames)
	if err != nil {
		return nil, err
	}

	zapLogger.Info("generating quote")
	quote, err := c.qi.Issue(cert.Raw)
	if err != nil {
		zapLogger.Warn("Failed to get quote. Proceeding in simulation mode.")
		// If we run in SimulationMode we get an error here
		// For testing purpose we do not want to just fail here
		// Instead we store an empty quote that will make it transparent to the client that the integrity of the mesh can not be guaranteed.
		c.quote = []byte{}
	} else {
		c.quote = quote
	}

	c.cert = cert
	c.privk = privk
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
	cert, err := c.GetTLSCertificate()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}, nil
}

// GetTLSCertificate creates a TLS certificate for the Coordinators self-signed x509 certificate
func (c *Core) GetTLSCertificate() (*tls.Certificate, error) {
	if c.state == stateUninitialized {
		return nil, errors.New("don't have a cert yet")
	}
	return util.TLSCertFromDER(c.cert.Raw, c.privk), nil
}

func (c *Core) loadState(dnsNames []string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	stateRaw, err := c.sealer.Unseal()

	// If dnsNames is nil, the function call has likely been invoked by the /recover API. If it is not nil, it is likely the coordinator starting up and we shall generate a new state by default.
	if err != nil && dnsNames == nil {
		c.zaplogger.Error("Failed to decrypt sealed state. Use the /recover API endpoint to load another decrypted recovery key.")
		c.state = stateRecovery
		return nil, nil, err
	} else if err != nil {
		c.zaplogger.Error("Failed to decrypt sealed state. Processing with a new state. Use the /recover API endpoint to load an old state, or submit a new manifest to overwrite the old state. Look up the documentation for more information on how to proceed.")
		c.state = stateRecovery
		return c.generateCert(dnsNames)
	}

	// generate new state if there isn't something in the fs yet
	if len(stateRaw) == 0 {
		c.zaplogger.Info("No sealed state found. Proceeding with new state.")
		return c.generateCert(dnsNames)
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
	if err := c.requireState(stateRecovery); err != nil {
		c.mux.Unlock()
		if err := c.requireState(stateUninitialized); err != nil {
			return nil, nil, err
		}
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

	if c.state == stateUninitialized {
		c.state = stateAcceptingManifest
	}

	return cert, privk, nil
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

func (c *Core) getStatus(ctx context.Context) (string, error) {
	return "this is a test status", nil
}
