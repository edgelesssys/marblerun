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
	"math"
	"text/template"
	"time"

	"github.com/edgelesssys/ego/marble"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"github.com/edgelesssys/marblerun/util"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type reservedSecrets struct {
	RootCA     manifest.Secret
	MarbleCert manifest.Secret
	SealKey    manifest.Secret
}

// Defines the "Marblerun" prefix when mentioned in a manifest
type secretsWrapper struct {
	Marblerun reservedSecrets
	Secrets   map[string]manifest.Secret
}

// Activate implements the MarbleAPI function to authenticate a marble (implements the MarbleServer interface)
//
// Verifies the marble's integritiy and subsequently provides the marble with a certificate for authentication and application-specific parameters as defined in the Coordinator's manifest.
//
// req needs to contain a MarbleType present in the Coordinator's manifest and a CSR with the Subject and DNSNames set with desired values.
//
// Returns a signed certificate-key-pair and the application's parameters if the authentication was successful.
// Returns an error if the authentication failed.
func (c *Core) Activate(ctx context.Context, req *rpc.ActivationReq) (*rpc.ActivationResp, error) {
	c.zaplogger.Info("Received activation request", zap.String("MarbleType", req.MarbleType))
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

	// Generate user-defined unique (= per marble) secrets
	secrets, err := c.generateSecrets(ctx, c.manifest.Secrets, marbleUUID, c.intermediateCert, c.intermediatePrivK)
	if err != nil {
		c.zaplogger.Error("Could not generate specified secrets for the given manifest.", zap.Error(err))
		return nil, err
	}

	// Union user-defined unique secrets with user-defined shared secrets
	for k, v := range c.secrets {
		secrets[k] = v
	}

	marble := c.manifest.Marbles[req.GetMarbleType()] // existence has been checked in verifyManifestRequirement
	// add TTLS config to Env
	if err := c.setTTLSConfig(marble); err != nil {
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

	c.zaplogger.Info("Successfully activated new Marble", zap.String("MarbleType", req.MarbleType), zap.String("UUID", marbleUUID.String()))
	c.activations[req.GetMarbleType()]++
	return resp, nil
}

// verifyManifestRequirement verifies marble attempting to register with respect to manifest
func (c *Core) verifyManifestRequirement(tlsCert *x509.Certificate, certQuote []byte, marbleType string) error {
	marble, ok := c.manifest.Marbles[marbleType]
	if !ok {
		return status.Error(codes.InvalidArgument, "unknown marble type requested")
	}

	pkg, ok := c.manifest.Packages[marble.Package]
	if !ok {
		// can't happen
		return status.Error(codes.Internal, "undefined package")
	}

	// In case the administrator has updated a package, apply the updated security version
	if updpkg, ok := c.updateManifest.Packages[marble.Package]; ok {
		pkg.SecurityVersion = updpkg.SecurityVersion
	}

	if !c.inSimulationMode() {
		if len(c.manifest.Infrastructures) == 0 {
			if err := c.qv.Validate(certQuote, tlsCert.Raw, pkg, quote.InfrastructureProperties{}); err != nil {
				return status.Errorf(codes.Unauthenticated, "invalid quote: %v", err)
			}
		} else {
			infraMatch := false
			for _, infra := range c.manifest.Infrastructures {
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
	activations := c.activations[marbleType]
	if marble.MaxActivations > 0 && activations >= marble.MaxActivations {
		return status.Error(codes.ResourceExhausted, "reached max activations count for marble type")
	}
	return nil
}

// generateCertFromCSR signs the CSR from marble attempting to register
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

	// create certificate
	csr.Subject.CommonName = marbleUUID
	csr.Subject.Organization = c.intermediateCert.Issuer.Organization
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

	certRaw, err := x509.CreateCertificate(rand.Reader, &template, c.intermediateCert, &pubk, c.intermediatePrivK)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to issue certificate")
	}

	return certRaw, nil
}

// customizeParameters replaces the placeholders in the manifest's parameters with the actual values
func customizeParameters(params *rpc.Parameters, specialSecrets reservedSecrets, userSecrets map[string]manifest.Secret) (*rpc.Parameters, error) {
	customParams := rpc.Parameters{
		Argv:  params.Argv,
		Files: make(map[string]string),
		Env:   make(map[string]string),
	}

	// Wrap the authentication secrets to have the "Marblerun" prefix in front of them when mentioned in a manifest
	secretsWrapped := secretsWrapper{
		Marblerun: specialSecrets,
		Secrets:   userSecrets,
	}

	// replace placeholders in files
	for path, data := range params.Files {
		newValue, err := parseSecrets(data, secretsWrapped)
		if err != nil {
			return nil, err
		}

		customParams.Files[path] = newValue
	}

	for name, data := range params.Env {
		newValue, err := parseSecrets(data, secretsWrapped)
		if err != nil {
			return nil, err
		}

		customParams.Env[name] = newValue
	}

	// Set as environment variables
	intermediateCaPem, err := manifest.EncodeSecretDataToPem(specialSecrets.RootCA.Cert)
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

	customParams.Env[marble.MarbleEnvironmentIntermediateCA] = intermediateCaPem
	customParams.Env[marble.MarbleEnvironmentCertificateChain] = marbleCertPem + intermediateCaPem
	customParams.Env[marble.MarbleEnvironmentPrivateKey] = encodedPrivKey

	return &customParams, nil
}

func parseSecrets(data string, secretsWrapped secretsWrapper) (string, error) {
	var templateResult bytes.Buffer

	tpl, err := template.New("data").Funcs(manifest.ManifestTemplateFuncMap).Parse(data)
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

	// Derive sealing key for marble
	uuidBytes, err := marbleUUID.MarshalBinary()
	if err != nil {
		return reservedSecrets{}, err
	}
	sealKey, err := util.DeriveKey(c.rootPrivK.D.Bytes(), uuidBytes, 32)
	if err != nil {
		return reservedSecrets{}, err
	}

	certRaw, err := c.generateCertFromCSR(req.GetCSR(), privk.PublicKey, req.GetMarbleType(), marbleUUID.String())
	if err != nil {
		return reservedSecrets{}, err
	}

	marbleCert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return reservedSecrets{}, err
	}

	// customize marble's parameters
	authSecrets := reservedSecrets{
		RootCA:     manifest.Secret{Cert: manifest.Certificate(*c.intermediateCert)},
		MarbleCert: manifest.Secret{Cert: manifest.Certificate(*marbleCert), Public: encodedPubKey, Private: encodedPrivKey},
		SealKey:    manifest.Secret{Public: sealKey, Private: sealKey},
	}

	return authSecrets, nil
}

func (c *Core) setTTLSConfig(marble manifest.Marble) error {
	if len(marble.TLS) == 0 {
		return nil
	}

	ttlsConf := make(map[string]map[string]string)
	ttlsConf["tls"] = make(map[string]string)
	for _, tag := range marble.TLS {
		for _, entry := range c.manifest.TLS[tag].Outgoing {
			pemCert := pem.Block{Type: "CERTIFICATE", Bytes: c.intermediateCert.Raw}
			ttlsConf["tls"][entry.Addr+":"+entry.Port] = string(pem.EncodeToMemory(&pemCert))
		}
	}
	ttlsConfJSON, err := json.Marshal(ttlsConf)
	if err != nil {
		return err
	}
	if marble.Parameters.Env == nil {
		marble.Parameters.Env = make(map[string]string)
	}
	marble.Parameters.Env["MARBLE_TTLS_CONFIG"] = string(ttlsConfJSON)

	return nil
}
