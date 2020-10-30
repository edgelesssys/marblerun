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
	"log"
	"math"
	"net"
	"sync"
	"time"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/util"
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
}

// The sequence of states a Coordinator may be in
type state int

const (
	stateUninitialized state = iota
	stateAcceptingManifest
	stateAcceptingMarbles
)

// sealedState represents the state information, required for persistence, that gets sealed to the filesystem
type sealedState struct {
	Privk          []byte
	RawManifest    []byte
	RawCert        []byte
	State          state
	ActivationsMap map[string]uint
}

const coordinatorName string = "Coordinator"

// Needs to be paired with `defer c.mux.Unlock()`
func (c *Core) requireState(state state) error {
	c.mux.Lock()
	if c.state != state {
		return errors.New("server is not in expected state")
	}
	return nil
}

func (c *Core) advanceState() {
	c.state++
}

// NewCore creates and initializes a new Core object
func NewCore(orgName string, dnsNames []string, qv quote.Validator, qi quote.Issuer, sealer Sealer) (*Core, error) {
	c := &Core{
		state:       stateUninitialized,
		activations: make(map[string]uint),
		qv:          qv,
		qi:          qi,
		sealer:      sealer,
	}

	log.Println("loading state")
	cert, privk, err := c.loadState(orgName, dnsNames)
	if err != nil {
		return nil, err
	}

	log.Println("generating quote")
	quote, err := c.qi.Issue(cert.Raw)
	if err != nil {
		log.Println("failed to get quote. Proceeding in simulation mode")
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

// GetQuote gets the quote of the server
func (c *Core) GetQuote(ctx context.Context) ([]byte, error) {
	if c.state == uninitialized {
		return nil, errors.New("don't have a cert or quote yet")
	}
	return c.quote, nil
}

// NewCoreWithMocks creates a new core object with quote and seal mocks for testing.
func NewCoreWithMocks() *Core {
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &MockSealer{}
	core, err := NewCore("edgeless", []string{"localhost"}, validator, issuer, sealer)
	if err != nil {
		panic(err)
	}
	return core
}

// InSimulationMode returns true if we operate in OE_SIMULATION mode
func (c *Core) InSimulationMode() bool {
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

func (c *Core) loadState(orgName string, dnsNames []string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	stateRaw, err := c.sealer.Unseal()
	if err != nil {
		return nil, nil, err
	}
	// generate new state if there isn't something in the fs yet
	if len(stateRaw) == 0 {
		log.Println("no sealed state found. Proceeding with new state")
		return c.generateCert(orgName, dnsNames)
	}
	// load state
	log.Println("loading state from fs")
	var loadedState sealedState
	if err := json.Unmarshal(stateRaw, &loadedState); err != nil {
		return nil, nil, err
	}
	// set Core to loaded state
	if err := json.Unmarshal(loadedState.RawManifest, &c.manifest); err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(loadedState.RawCert)
	if err != nil {
		return nil, nil, err
	}
	privk, err := x509.ParseECPrivateKey(loadedState.Privk)
	if err != nil {
		return nil, nil, err
	}
	c.state = loadedState.State
	c.activations = loadedState.ActivationsMap
	return cert, privk, err
}

func (c *Core) sealState() error {
	// marshal private key
	x509Encoded, err := x509.MarshalECPrivateKey(c.privk)
	if err != nil {
		return err
	}
	// seal with manifest set
	state := sealedState{
		Privk:          x509Encoded,
		RawManifest:    c.rawManifest,
		RawCert:        c.cert.Raw,
		State:          c.state,
		ActivationsMap: c.activations,
	}
	stateRaw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return c.sealer.Seal(stateRaw)
}

func (c *Core) generateCert(orgName string, dnsNames []string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	defer c.mux.Unlock()
	if err := c.requireState(stateUninitialized); err != nil {
		return nil, nil, err
	}

	// code (including generateSerial()) adapted from golang.org/src/crypto/tls/generate_cert.go
	privk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubk := privk.PublicKey
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
			Organization: []string{orgName},
			CommonName:   coordinatorName,
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

	certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, &pubk, privk)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return nil, nil, err
	}
	c.advanceState()
	return cert, privk, nil
}

func getClientTLSCert(ctx context.Context) *x509.Certificate {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}
	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	// the following check is just for safety (not for security)
	if !ok {
		return nil
	}
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil
	}
	return tlsInfo.State.PeerCertificates[0]
}

func (c *Core) getStatus(ctx context.Context) (string, error) {
	return "this is a test status", nil
	//return nil, errors.New("getStatus is not yet implemented")
}
