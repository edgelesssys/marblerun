package core

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/edgelesssys/coordinator/coordinator/quote"
)

// Core implements the core logic of the Coordinator
type Core struct {
	cert        *x509.Certificate
	quote       []byte
	privk       ed25519.PrivateKey
	sealDir     string
	sealKey     []byte
	manifest    Manifest
	rawManifest []byte
	state       state
	qv          quote.Validator
	qi          quote.Issuer
	activations map[string]uint
	mux         sync.Mutex
}

// sealedState represents the state information, required for persistence, that gets sealed to the filesystem
type sealedState struct {
	Privk    ed25519.PrivateKey
	Manifest Manifest
	Cert     x509.Certificate
	State    state
}

// The sequence of states a Coordinator may be in
type state int

const (
	uninitialized state = iota
	acceptingManifest
	acceptingMarbles
	closed
)

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
func NewCore(orgName string, qv quote.Validator, qi quote.Issuer, sealDir string, sealKey []byte) (*Core, error) {
	c := &Core{
		state:       uninitialized,
		activations: make(map[string]uint),
		qv:          qv,
		qi:          qi,
		sealDir:     sealDir,
		sealKey:     sealKey,
	}
	if err := c.loadState(orgName); err != nil {
		return nil, err
	}
	return c, nil
}

// GetQuote gets the quote of the server
func (c *Core) GetQuote(ctx context.Context) ([]byte, error) {
	if c.state == uninitialized {
		return nil, errors.New("don't have a cert or quote yet")
	}
	return c.quote, nil
}

func (c *Core) getCert(ctx context.Context) (*x509.Certificate, error) {
	if c.state == uninitialized {
		return nil, errors.New("don't have a cert yet")
	}
	return c.cert, nil
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
	if c.state == uninitialized {
		return nil, errors.New("don't have a cert yet")
	}
	return tlsCertFromDER(c.cert.Raw, c.privk), nil
}

func (c *Core) loadState(orgName string) error {
	loadedState, err := unsealData(c.sealDir, c.sealKey)
	if err != nil {
		return err
	}
	// generate new state if there isn't something in the fs yet
	if loadedState == nil {
		if err := c.generateCert(orgName); err != nil {
			return err
		}
		return nil
	}
	// set Core to loaded state
	c.privk = loadedState.Privk
	c.manifest = loadedState.Manifest
	c.cert = &loadedState.Cert
	quote, err := c.qi.Issue(c.cert.Raw)
	if err != nil {
		return err
	}
	c.quote = quote
	c.state = loadedState.State
	return nil
}

func (c *Core) sealState() error {
	// seal with manifest set
	data := sealedState{
		Privk:    c.privk,
		Manifest: c.manifest,
		Cert:     *c.cert,
		State:    c.state,
	}
	if err := sealData(c.sealDir, data, c.sealKey); err != nil {
		return err
	}
	return nil
}

// loadPrivateKey reads the coordinator's sealed data  from the fs if present
func unsealData(secretDir string, sealKey []byte) (*sealedState, error) {
	// load from fs
	nonceFname := filepath.Join(secretDir, "nonce")
	keyFname := filepath.Join(secretDir, "sealed_data")
	nonce, err := ioutil.ReadFile(nonceFname)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	sealedBytes, err := ioutil.ReadFile(keyFname)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	// decrypt
	block, err := aes.NewCipher(sealKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	dataRaw, err := aesgcm.Open(nil, nonce, sealedBytes, nil)
	if err != nil {
		return nil, err
	}

	// unmarsahl
	var data sealedState
	if err := json.Unmarshal(dataRaw, &data); err != nil {
		return nil, err
	}

	return &data, nil
}

// sealData stores the coordinator's data sealed to the fs
func sealData(secretDir string, data sealedState, sealKey []byte) error {
	nonceFname := filepath.Join(secretDir, "nonce")
	keyFname := filepath.Join(secretDir, "sealed_data")

	// marshal
	dataRaw, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// encrypt
	block, err := aes.NewCipher(sealKey)
	if err != nil {
		return err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	sealedKey := aesgcm.Seal(nil, nonce, dataRaw, nil)

	// store to fs
	if err := ioutil.WriteFile(nonceFname, nonce, 0600); err != nil {
		return err
	}
	if err := ioutil.WriteFile(keyFname, sealedKey, 0600); err != nil {
		return err
	}
	return nil
}

func generateSerial() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

func (c *Core) generateCert(orgName string) error {
	defer c.mux.Unlock()
	if err := c.requireState(uninitialized); err != nil {
		return err
	}

	// code (including generateSerial()) adapted from golang.org/src/crypto/tls/generate_cert.go
	pubk, privk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(math.MaxInt64)

	serialNumber, err := generateSerial()
	if err != nil {
		return err
	}

	// TODO: what else do we need to set here?
	// Do we need x509.KeyUsageKeyEncipherment?
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{orgName},
			CommonName:   coordinatorName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, pubk, privk)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return err
	}
	quote, err := c.qi.Issue(certRaw)
	if err != nil {
		return err
	}
	c.cert = cert
	c.quote = quote
	c.privk = privk
	c.advanceState()
	return nil
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

func tlsCertFromDER(certDER []byte, privk interface{}) *tls.Certificate {
	return &tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: privk}
}
func (c *Core) getStatus(ctx context.Context) (string, error) {
	return "this is a test status", nil
	//return nil, errors.New("getStatus is not yet implemented")
}
