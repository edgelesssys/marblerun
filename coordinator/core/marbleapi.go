// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"text/template"
	"time"

	"github.com/edgelesssys/ego/marble"
	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store"
	"github.com/edgelesssys/marblerun/coordinator/store/request"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper"
	"github.com/edgelesssys/marblerun/util"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type reservedSecrets struct {
	RootCA     manifest.Secret
	MarbleCert manifest.Secret
}

// Defines the "MarbleRun" prefix when mentioned in a manifest.
type secretsWrapper struct {
	MarbleRun reservedSecrets
	Secrets   map[string]manifest.Secret
}

// Activate implements the MarbleAPI function to authenticate a marble (implements the MarbleServer interface).
//
// Verifies the marble's integrity and subsequently provides the marble with a certificate for authentication and application-specific parameters as defined in the Coordinator's manifest.
//
// Parameter req needs to contain a MarbleType present in the Coordinator's manifest and a CSR with the Subject and DNSNames set with desired values.
//
// Returns a signed certificate-key-pair and the application's parameters if the authentication was successful.
// Returns an error if the authentication failed.
func (c *Core) Activate(ctx context.Context, req *rpc.ActivationReq) (res *rpc.ActivationResp, err error) {
	c.log.Info("Received activation request", zap.String("MarbleType", req.MarbleType))
	c.metrics.marbleAPI.activation.WithLabelValues(req.GetMarbleType(), req.GetUUID()).Inc()

	defer c.mux.Unlock()
	if err := c.RequireState(state.AcceptingMarbles); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "cannot accept marbles in current state")
	}

	defer func() {
		if err != nil {
			c.log.Error("Marble Activation failed", zap.String("marbleType", req.GetMarbleType()), zap.String("uuid", req.GetUUID()))
		}
	}()

	// get the marble's TLS cert (used in this connection) and check corresponding quote
	tlsCert := getClientTLSCert(ctx)
	if tlsCert == nil {
		c.log.Error("Couldn't get marble TLS certificate")
		return nil, status.Error(codes.Unauthenticated, "couldn't get marble TLS certificate")
	}

	tx, err := c.store.BeginTransaction()
	if err != nil {
		c.log.Error("Initialize store transaction failed", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "initializing store transaction: %s", err)
	}
	defer tx.Rollback()
	txdata := wrapper.New(tx)

	if err := c.verifyManifestRequirement(txdata, tlsCert, req.GetQuote(), req.GetMarbleType()); err != nil {
		c.log.Error("Marble verification failed", zap.Error(err))
		return nil, status.Errorf(codes.PermissionDenied, "marble verification failed: %s", err)
	}

	marbleUUID, err := uuid.Parse(req.GetUUID())
	if err != nil {
		c.log.Error("Invalid UUID", zap.Error(err))
		return nil, status.Errorf(codes.InvalidArgument, "invalid UUID: %s", err)
	}

	// Generate marble authentication secrets
	authSecrets, err := c.generateMarbleAuthSecrets(txdata, req, marbleUUID)
	if err != nil {
		c.log.Error("Generating marble authentication secrets failed", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "generating marble authentication secrets: %s", err)
	}

	marbleRootCert, err := txdata.GetCertificate(constants.SKMarbleRootCert)
	if err != nil {
		c.log.Error("Couldn't retrieve marble root certificate", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "retrieving marbleRootCert certificate: %s", err)
	}
	rootPrivK, err := txdata.GetPrivateKey(constants.SKCoordinatorRootKey)
	if err != nil {
		c.log.Error("Couldn't retrieve marbleRootCert private key", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "retrieving marble root private key: %s", err)
	}
	intermediatePrivK, err := txdata.GetPrivateKey(constants.SKCoordinatorIntermediateKey)
	if err != nil {
		c.log.Error("Couldn't retrieve marbleRootCert private key", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "retrieving marble root private key: %s", err)
	}

	secrets, err := txdata.GetSecretMap()
	if err != nil {
		c.log.Error("Loading secrets from store failed", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "retrieving secrets: %s", err)
	}

	// Generate unique (= per marble) secrets
	privateSecrets, err := c.GenerateSecrets(secrets, marbleUUID, marbleRootCert, intermediatePrivK, rootPrivK)
	if err != nil {
		c.log.Error("Couldn't generate specified secrets for the given manifest", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "generating secrets for marble: %s", err)
	}

	// Union newly generated unique secrets with shared and user-defined secrets
	for k, v := range privateSecrets {
		secrets[k] = v
	}

	marble, err := txdata.GetMarble(req.MarbleType)
	if err != nil {
		c.log.Error("Loading marble config failed", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "retrieving marble config: %s", err)
	}

	// add TTLS config to Env
	if err := c.setTTLSConfig(txdata, marble, authSecrets, secrets); err != nil {
		c.log.Error("Couldn't create TTLS config", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "creating TTLS config: %s", err)
	}

	params, err := customizeParameters(marble.Parameters, authSecrets, secrets)
	if err != nil {
		c.log.Error("Customizing marble parameters failed", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "customizing marble parameters: %s", err)
	}

	// write response
	resp := &rpc.ActivationResp{
		Parameters: params,
	}

	// We only need to commit any data to the store if we have a limit on the number of activations
	if marble.MaxActivations > 0 {
		if err := txdata.IncrementActivations(req.GetMarbleType()); err != nil {
			c.log.Error("Could not increment activations", zap.Error(err))
			return nil, status.Errorf(codes.Internal, "incrementing marble activations: %s", err)
		}
		if err := tx.Commit(); err != nil {
			c.log.Error("Committing store transaction failed", zap.Error(err))
			return nil, status.Errorf(codes.Internal, "committing store transaction: %s", err)
		}
	}

	c.metrics.marbleAPI.activationSuccess.WithLabelValues(req.GetMarbleType(), req.GetUUID()).Inc()
	c.log.Info("Successfully activated new Marble", zap.String("MarbleType", req.MarbleType), zap.String("UUID", marbleUUID.String()))

	if c.eventlog != nil {
		c.eventlog.Activation(req.GetMarbleType(), req.GetUUID(), req.GetQuote())
	}

	return resp, nil
}

// verifyManifestRequirement verifies marble attempting to register with respect to manifest.
func (c *Core) verifyManifestRequirement(txdata storeGetter, tlsCert *x509.Certificate, certQuote []byte, marbleType string) error {
	marble, err := txdata.GetMarble(marbleType)
	if err != nil {
		if errors.Is(err, store.ErrValueUnset) {
			return fmt.Errorf("unknown marble type requested")
		}
		return fmt.Errorf("loading marble data: %w", err)
	}

	pkg, err := txdata.GetPackage(marble.Package)
	if err != nil {
		if errors.Is(err, store.ErrValueUnset) {
			return fmt.Errorf("undefined package %q", marble.Package)
		}
		return fmt.Errorf("loading package data: %w", err)
	}

	infraIter, err := txdata.GetIterator(request.Infrastructure)
	if err != nil {
		return fmt.Errorf("getting infrastructure iterator: %w", err)
	}

	if !c.inSimulationMode() {
		if !infraIter.HasNext() {
			if err := c.qv.Validate(certQuote, tlsCert.Raw, pkg, quote.InfrastructureProperties{}); err != nil {
				return fmt.Errorf("invalid quote: %w", err)
			}
		} else {
			infraMatch := false
			for infraIter.HasNext() {
				infraName, err := infraIter.GetNext()
				if err != nil {
					return err
				}
				infra, err := txdata.GetInfrastructure(infraName)
				if err != nil {
					return fmt.Errorf("loading infrastructure: %w", err)
				}
				if c.qv.Validate(certQuote, tlsCert.Raw, pkg, infra) == nil {
					infraMatch = true
					break
				}
			}
			if !infraMatch {
				return fmt.Errorf("invalid infrastructure")
			}
		}
	}

	// check activation budget (MaxActivations == 0 means infinite budget)
	activations, err := txdata.GetActivations(marbleType)
	if err != nil {
		return fmt.Errorf("could not retrieve activations for marble type %q: %w", marbleType, err)
	}
	if marble.MaxActivations > 0 && activations >= marble.MaxActivations {
		return fmt.Errorf("reached max activations count (%d) for marble type %q", marble.MaxActivations, marbleType)
	}
	return nil
}

// generateCertFromCSR signs the CSR from marble attempting to register.
func (c *Core) generateCertFromCSR(txdata storeGetter, csrReq []byte, pubk ecdsa.PublicKey, marbleUUID string) ([]byte, error) {
	// parse and verify CSR
	csr, err := x509.ParseCertificateRequest(csrReq)
	if err != nil {
		return nil, fmt.Errorf("parsing CSR: %w", err)
	}
	if csr.CheckSignature() != nil {
		return nil, fmt.Errorf("signature over CSR is invalid")
	}

	serialNumber, err := util.GenerateCertificateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generating certificate serial number: %w", err)
	}

	marbleRootCert, err := txdata.GetCertificate(constants.SKMarbleRootCert)
	if err != nil {
		return nil, fmt.Errorf("loading marble root certificate: %w", err)
	}
	intermediatePrivK, err := txdata.GetPrivateKey(constants.SKCoordinatorIntermediateKey)
	if err != nil {
		return nil, fmt.Errorf("loading marble root certificate private key: %w", err)
	}

	// create certificate
	csr.Subject.CommonName = marbleUUID
	csr.Subject.Organization = marbleRootCert.Issuer.Organization
	notBefore := time.Now()
	// TODO: produce shorter lived certificates
	notAfter := notBefore.Add(math.MaxInt64)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
	}

	certRaw, err := x509.CreateCertificate(rand.Reader, &template, marbleRootCert, &pubk, intermediatePrivK)
	if err != nil {
		return nil, fmt.Errorf("issuing marble certificate: %w", err)
	}

	return certRaw, nil
}

// customizeParameters replaces the placeholders in the manifest's parameters with the actual values.
func customizeParameters(params manifest.Parameters, specialSecrets reservedSecrets, userSecrets map[string]manifest.Secret) (*rpc.Parameters, error) {
	customParams := rpc.Parameters{
		Argv:  params.Argv,
		Files: make(map[string][]byte),
		Env:   make(map[string][]byte),
	}

	// Wrap the authentication secrets to have the "MarbleRun" prefix in front of them when mentioned in a manifest
	secretsWrapped := secretsWrapper{
		MarbleRun: specialSecrets,
		Secrets:   userSecrets,
	}

	var err error
	var newValue string

	// replace placeholders in files
	for path, data := range params.Files {
		if data.NoTemplates {
			newValue = data.Data
		} else {
			newValue, err = parseSecrets(data.Data, manifest.ManifestFileTemplateFuncMap, secretsWrapped)
			if err != nil {
				return nil, fmt.Errorf("parsing secrets for file %q: %w", path, err)
			}
		}

		customParams.Files[path] = []byte(newValue)
	}

	for name, data := range params.Env {
		if data.NoTemplates {
			newValue = data.Data
		} else {
			newValue, err = parseSecrets(data.Data, manifest.ManifestEnvTemplateFuncMap, secretsWrapped)
			if err != nil {
				return nil, fmt.Errorf("parsing secrets for env variable %q: %w", name, err)
			}
		}

		customParams.Env[name] = []byte(newValue)
	}

	// Set as environment variables
	rootCaPem, err := manifest.EncodeSecretDataToPem(specialSecrets.RootCA.Cert)
	if err != nil {
		return nil, fmt.Errorf("encoding root CA: %w", err)
	}
	marbleCertPem, err := manifest.EncodeSecretDataToPem(specialSecrets.MarbleCert.Cert)
	if err != nil {
		return nil, fmt.Errorf("encoding marble certificate: %w", err)
	}
	encodedPrivKey, err := manifest.EncodeSecretDataToPem(specialSecrets.MarbleCert.Private)
	if err != nil {
		return nil, fmt.Errorf("encoding marble private key: %w", err)
	}

	customParams.Env[marble.MarbleEnvironmentRootCA] = []byte(rootCaPem)
	customParams.Env[marble.MarbleEnvironmentCertificateChain] = []byte(marbleCertPem + rootCaPem)
	customParams.Env[marble.MarbleEnvironmentPrivateKey] = []byte(encodedPrivKey)

	return &customParams, nil
}

func parseSecrets(data string, tplFunc template.FuncMap, secretsWrapped secretsWrapper) (string, error) {
	var templateResult bytes.Buffer

	tpl, err := template.New("data").Funcs(tplFunc).Parse(data)
	if err != nil {
		return "", err
	}

	if err := tpl.Execute(&templateResult, secretsWrapped); err != nil {
		return "", err
	}

	return templateResult.String(), nil
}

func (c *Core) generateMarbleAuthSecrets(txdata storeGetter, req *rpc.ActivationReq, marbleUUID uuid.UUID) (reservedSecrets, error) {
	// generate key-pair for marble
	privk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return reservedSecrets{}, err
	}
	encodedPrivKey, err := x509.MarshalPKCS8PrivateKey(privk)
	if err != nil {
		return reservedSecrets{}, err
	}
	encodedPubKey, err := x509.MarshalPKIXPublicKey(&privk.PublicKey)
	if err != nil {
		return reservedSecrets{}, err
	}

	// Generate Marble certificate
	certRaw, err := c.generateCertFromCSR(txdata, req.GetCSR(), privk.PublicKey, marbleUUID.String())
	if err != nil {
		return reservedSecrets{}, err
	}

	marbleCert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return reservedSecrets{}, err
	}

	marbleRootCert, err := txdata.GetCertificate(constants.SKMarbleRootCert)
	if err != nil {
		return reservedSecrets{}, err
	}
	// customize marble's parameters
	authSecrets := reservedSecrets{
		RootCA:     manifest.Secret{Cert: manifest.Certificate(*marbleRootCert)},
		MarbleCert: manifest.Secret{Cert: manifest.Certificate(*marbleCert), Public: encodedPubKey, Private: encodedPrivKey},
	}

	return authSecrets, nil
}

func (c *Core) setTTLSConfig(txdata storeGetter, marble manifest.Marble, specialSecrets reservedSecrets, userSecrets map[string]manifest.Secret) error {
	if len(marble.TLS) == 0 {
		return nil
	}

	ttlsConf := make(map[string]map[string]map[string]map[string]interface{})
	ttlsConf["tls"] = make(map[string]map[string]map[string]interface{})
	ttlsConf["tls"]["Incoming"] = make(map[string]map[string]interface{})
	ttlsConf["tls"]["Outgoing"] = make(map[string]map[string]interface{})

	marbleRootCert, err := txdata.GetCertificate(constants.SKMarbleRootCert)
	if err != nil {
		return err
	}

	pemCaCert := pem.Block{Type: "CERTIFICATE", Bytes: marbleRootCert.Raw}
	stringCaCert := string(pem.EncodeToMemory(&pemCaCert))

	pemClientCert := pem.Block{Type: "CERTIFICATE", Bytes: specialSecrets.MarbleCert.Cert.Raw}
	stringClientCert := string(pem.EncodeToMemory(&pemClientCert))

	pemClientKey := pem.Block{Type: "PRIVATE KEY", Bytes: specialSecrets.MarbleCert.Private}
	stringClientKey := string(pem.EncodeToMemory(&pemClientKey))

	for _, tagName := range marble.TLS {
		tag, err := txdata.GetTLS(tagName)
		if err != nil {
			return err
		}
		for _, entry := range tag.Outgoing {
			connConf := make(map[string]interface{})
			connConf["cacrt"] = stringCaCert
			connConf["clicrt"] = stringClientCert
			connConf["clikey"] = stringClientKey

			ttlsConf["tls"]["Outgoing"][entry.Addr+":"+entry.Port] = connConf
		}
		for _, entry := range tag.Incoming {
			connConf := make(map[string]interface{})

			// use user-defined values if present
			if entry.Cert != "" {
				pemUserClientCert := pem.Block{Type: "CERTIFICATE", Bytes: userSecrets[entry.Cert].Cert.Raw}
				stringUserClientCert := string(pem.EncodeToMemory(&pemUserClientCert))

				pemUserClientKey := pem.Block{Type: "PRIVATE KEY", Bytes: userSecrets[entry.Cert].Private}
				stringUserClientKey := string(pem.EncodeToMemory(&pemUserClientKey))

				connConf["clicrt"] = stringUserClientCert
				connConf["clikey"] = stringUserClientKey
				connConf["clientAuth"] = !entry.DisableClientAuth
				connConf["cacrt"] = stringCaCert
			} else {
				connConf["cacrt"] = stringCaCert
				connConf["clicrt"] = stringClientCert
				connConf["clikey"] = stringClientKey
				connConf["clientAuth"] = true
			}

			ttlsConf["tls"]["Incoming"]["*:"+entry.Port] = connConf
		}
	}

	ttlsConfJSON, err := json.Marshal(ttlsConf)
	if err != nil {
		return err
	}
	if marble.Parameters.Env == nil {
		marble.Parameters.Env = make(map[string]manifest.File)
	}
	marble.Parameters.Env["MARBLE_TTLS_CONFIG"] = manifest.File{Data: string(ttlsConfJSON), Encoding: "string"}

	return nil
}
