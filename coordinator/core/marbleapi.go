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
	"fmt"
	"math"
	"text/template"
	"time"

	"github.com/edgelesssys/ego/marble"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"github.com/edgelesssys/marblerun/coordinator/store"
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
func (c *Core) Activate(ctx context.Context, req *rpc.ActivationReq) (*rpc.ActivationResp, error) {
	c.zaplogger.Info("Received activation request", zap.String("MarbleType", req.MarbleType))
	c.metrics.marbleAPI.activation.WithLabelValues(req.GetMarbleType(), req.GetUUID()).Inc()

	defer c.mux.Unlock()
	if err := c.requireState(stateAcceptingMarbles); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "cannot accept marbles in current state")
	}

	// get the marble's TLS cert (used in this connection) and check corresponding quote
	tlsCert := getClientTLSCert(ctx)
	if tlsCert == nil {
		return nil, status.Error(codes.Unauthenticated, "couldn't get marble TLS certificate")
	}
	if err := c.verifyManifestRequirement(tlsCert, req.GetQuote(), req.GetMarbleType()); err != nil {
		return nil, err
	}

	marbleUUID, err := uuid.Parse(req.GetUUID())
	if err != nil {
		return nil, err
	}

	// Generate marble authentication secrets
	authSecrets, err := c.generateMarbleAuthSecrets(req, marbleUUID)
	if err != nil {
		return nil, err
	}

	marbleRootCert, err := c.data.getCertificate(sKMarbleRootCert)
	if err != nil {
		c.zaplogger.Error("Could not retrieve marbleRootCert certificate.", zap.Error(err))
		return nil, err
	}
	intermediatePrivK, err := c.data.getPrivK(sKCoordinatorIntermediateKey)
	if err != nil {
		c.zaplogger.Error("Could not retrieve marbleRootCert private key.", zap.Error(err))
	}

	secrets, err := c.data.getSecretMap()
	if err != nil {
		return nil, err
	}

	// Generate unique (= per marble) secrets
	privateSecrets, err := c.generateSecrets(ctx, secrets, marbleUUID, marbleRootCert, intermediatePrivK)
	if err != nil {
		c.zaplogger.Error("Could not generate specified secrets for the given manifest.", zap.Error(err))
		return nil, err
	}

	// Union newly generated unique secrets with shared and user-defined secrets
	for k, v := range privateSecrets {
		secrets[k] = v
	}

	marble, err := c.data.getMarble(req.MarbleType)
	if err != nil {
		return nil, err
	}

	// add TTLS config to Env
	if err := c.setTTLSConfig(marble, authSecrets, secrets); err != nil {
		c.zaplogger.Error("Could not create TTLS config.", zap.Error(err))
		return nil, err
	}

	params, err := customizeParameters(marble.Parameters, authSecrets, secrets)
	if err != nil {
		c.zaplogger.Error("Could not customize parameters.", zap.Error(err))
		return nil, err
	}

	// write response
	resp := &rpc.ActivationResp{
		Parameters: params,
	}

	tx, err := c.store.BeginTransaction()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if err := (storeWrapper{tx}).incrementActivations(req.GetMarbleType()); err != nil {
		c.zaplogger.Error("Could not increment activations.", zap.Error(err))
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	c.metrics.marbleAPI.activationSuccess.WithLabelValues(req.GetMarbleType(), req.GetUUID()).Inc()
	c.zaplogger.Info("Successfully activated new Marble", zap.String("MarbleType", req.MarbleType), zap.String("UUID", marbleUUID.String()))

	if c.eventlog != nil {
		c.eventlog.Activation(req.GetMarbleType(), req.GetUUID(), req.GetQuote())
	}


	return resp, nil
}

// verifyManifestRequirement verifies marble attempting to register with respect to manifest.
func (c *Core) verifyManifestRequirement(tlsCert *x509.Certificate, certQuote []byte, marbleType string) error {
	marble, err := c.data.getMarble(marbleType)
	if err != nil {
		if store.IsStoreValueUnsetError(err) {
			return status.Error(codes.InvalidArgument, "unknown marble type requested")
		}
		return status.Error(codes.Internal, fmt.Sprintf("unable to load marble data: %v", err))
	}

	pkg, err := c.data.getPackage(marble.Package)
	if err != nil {
		if store.IsStoreValueUnsetError(err) {
			return status.Error(codes.Internal, "undefined package")
		}
		return status.Error(codes.Internal, fmt.Sprintf("unable to load package data: %v", err))
	}

	infraIter, err := c.data.getIterator(requestInfrastructure)
	if err != nil {
		return err
	}

	if !c.inSimulationMode() {
		if !infraIter.HasNext() {
			if err := c.qv.Validate(certQuote, tlsCert.Raw, pkg, quote.InfrastructureProperties{}); err != nil {
				return status.Errorf(codes.Unauthenticated, "invalid quote: %v", err)
			}
		} else {
			infraMatch := false
			for infraIter.HasNext() {
				infraName, err := infraIter.GetNext()
				if err != nil {
					return err
				}
				infra, err := c.data.getInfrastructure(infraName)
				if err != nil {
					return err
				}
				if c.qv.Validate(certQuote, tlsCert.Raw, pkg, infra) == nil {
					infraMatch = true
					break
				}
			}
			if !infraMatch {
				return status.Error(codes.Unauthenticated, "invalid quote")
			}
		}
	}

	// check activation budget (MaxActivations == 0 means infinite budget)
	activations, err := c.data.getActivations(marbleType)
	if store.IsStoreValueUnsetError(err) {
		activations = 0
	} else if err != nil {
		return status.Error(codes.Internal, "could not retrieve activations for marble type")
	}
	if marble.MaxActivations > 0 && activations >= marble.MaxActivations {
		return status.Error(codes.ResourceExhausted, "reached max activations count for marble type")
	}
	return nil
}

// generateCertFromCSR signs the CSR from marble attempting to register.
func (c *Core) generateCertFromCSR(csrReq []byte, pubk ecdsa.PublicKey, marbleType string, marbleUUID string) ([]byte, error) {
	// parse and verify CSR
	csr, err := x509.ParseCertificateRequest(csrReq)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to parse CSR")
	}
	if csr.CheckSignature() != nil {
		return nil, status.Error(codes.InvalidArgument, "signature over CSR is invalid")
	}

	serialNumber, err := util.GenerateCertificateSerialNumber()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate serial")
	}

	marbleRootCert, err := c.data.getCertificate(sKMarbleRootCert)
	if err != nil {
		return nil, err
	}
	intermediatePrivK, err := c.data.getPrivK(sKCoordinatorIntermediateKey)
	if err != nil {
		return nil, err
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
		return nil, status.Error(codes.Internal, "failed to issue certificate")
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
				return nil, err
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
				return nil, err
			}
		}

		customParams.Env[name] = []byte(newValue)
	}

	// Set as environment variables
	rootCaPem, err := manifest.EncodeSecretDataToPem(specialSecrets.RootCA.Cert)
	if err != nil {
		return nil, err
	}
	marbleCertPem, err := manifest.EncodeSecretDataToPem(specialSecrets.MarbleCert.Cert)
	if err != nil {
		return nil, err
	}
	encodedPrivKey, err := manifest.EncodeSecretDataToPem(specialSecrets.MarbleCert.Private)
	if err != nil {
		return nil, err
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

func (c *Core) generateMarbleAuthSecrets(req *rpc.ActivationReq, marbleUUID uuid.UUID) (reservedSecrets, error) {
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
	certRaw, err := c.generateCertFromCSR(req.GetCSR(), privk.PublicKey, req.GetMarbleType(), marbleUUID.String())
	if err != nil {
		return reservedSecrets{}, err
	}

	marbleCert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return reservedSecrets{}, err
	}

	marbleRootCert, err := c.data.getCertificate(sKMarbleRootCert)
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

func (c *Core) setTTLSConfig(marble manifest.Marble, specialSecrets reservedSecrets, userSecrets map[string]manifest.Secret) error {
	if len(marble.TLS) == 0 {
		return nil
	}

	ttlsConf := make(map[string]map[string]map[string]map[string]interface{})
	ttlsConf["tls"] = make(map[string]map[string]map[string]interface{})
	ttlsConf["tls"]["Incoming"] = make(map[string]map[string]interface{})
	ttlsConf["tls"]["Outgoing"] = make(map[string]map[string]interface{})

	marbleRootCert, err := c.data.getCertificate(sKMarbleRootCert)
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
		tag, err := c.data.getTLS(tagName)
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
