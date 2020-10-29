package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"sync"
	"testing"
	"time"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/rpc"
	"github.com/edgelesssys/coordinator/test"
	"github.com/edgelesssys/coordinator/util"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestActivate(t *testing.T) {
	assert := assert.New(t)

	// parse manifest
	var manifest Manifest
	err := json.Unmarshal([]byte(test.ManifestJSON), &manifest)
	assert.Nil(err)

	// create core
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &MockSealer{}
	coreServer, err := NewCore("edgeless", []string{"localhost"}, validator, issuer, sealer)
	assert.NotNil(coreServer)
	assert.Nil(err)

	spawner := marbleSpawner{
		assert:     assert,
		issuer:     issuer,
		validator:  validator,
		manifest:   manifest,
		coreServer: coreServer,
	}

	// try to activate first backend marble prematurely before manifest is set
	spawner.newMarble("backend_first", "Azure", false)

	// set manifest
	assert.Nil(coreServer.SetManifest(context.TODO(), []byte(test.ManifestJSON)))

	// activate first backend
	spawner.newMarble("backend_first", "Azure", true)

	// try to activate another first backend
	spawner.newMarble("backend_first", "Azure", false)

	// activate 10 other backend
	pickInfra := func(i int) string {
		if i&1 == 0 {
			return "Azure"
		}
		return "Alibaba"
	}
	for i := 0; i < 10; i++ {
		spawner.newMarbleAsync("backend_other", pickInfra(i), true)
	}

	// activate 10 frontend
	for i := 0; i < 10; i++ {
		spawner.newMarbleAsync("frontend", pickInfra(i), true)
	}

	spawner.wg.Wait()
}

type marbleSpawner struct {
	manifest   Manifest
	validator  *quote.MockValidator
	issuer     quote.Issuer
	coreServer *Core
	assert     *assert.Assertions
	wg         sync.WaitGroup
}

func (ms *marbleSpawner) newMarble(marbleType string, infraName string, shouldSucceed bool) {
	cert, csr, _ := util.MustGenerateTestMarbleCredentials()

	// create mock quote using values from the manifest
	quote, err := ms.issuer.Issue(cert.Raw)
	ms.assert.NotNil(quote)
	ms.assert.Nil(err)
	marble, ok := ms.manifest.Marbles[marbleType]
	ms.assert.True(ok)
	pkg, ok := ms.manifest.Packages[marble.Package]
	ms.assert.True(ok)
	infra, ok := ms.manifest.Infrastructures[infraName]
	ms.assert.True(ok)
	ms.validator.AddValidQuote(quote, cert.Raw, pkg, infra)

	tlsInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		},
	}

	ctx := peer.NewContext(context.TODO(), &peer.Peer{
		AuthInfo: tlsInfo,
	})

	resp, err := ms.coreServer.Activate(ctx, &rpc.ActivationReq{
		CSR:        csr,
		MarbleType: marbleType,
		Quote:      quote,
		UUID:       uuid.New().String(),
	})

	if !shouldSucceed {
		ms.assert.NotNil(err)
		ms.assert.Nil(resp)
		return
	}
	ms.assert.Nil(err, "Activate failed: %v", err)
	ms.assert.NotNil(resp)

	// Validate response
	params := resp.GetParameters()
	// Validate Files
	if marble.Parameters.Files != nil {
		ms.assert.Equal(marble.Parameters.Files, params.Files)
	}
	// Validate Argv
	if marble.Parameters.Argv != nil {
		ms.assert.Equal(marble.Parameters.Argv, params.Argv)
	}

	// Validate SealKey
	sealKey, err := hex.DecodeString(params.Env["SEAL_KEY"])
	ms.assert.NoError(err)
	ms.assert.Len(sealKey, 32)

	// Validate Marble Key
	pemMarbleKey := resp.GetParameters().Env["MARBLE_KEY"]
	ms.assert.NotNil(pemMarbleKey)
	p, _ = pem.Decode([]byte(pemMarbleKey))
	ms.assert.NotNil(p)

	// Validate Cert
	pemCert := resp.GetParameters().Env["MARBLE_CERT"]
	ms.assert.NotNil(pemCert)
	p, _ = pem.Decode([]byte(pemCert))
	ms.assert.NotNil(p)
	newCert, err := x509.ParseCertificate(p.Bytes)
	ms.assert.Nil(err)
	ms.assert.Equal(coordinatorName, newCert.Issuer.CommonName)
	// Check CommonName
	_, err = uuid.Parse(newCert.Subject.CommonName)
	ms.assert.Nil(err, "cert.Subject.CommonName is not a valid UUID: %v", err)
	// Check KeyUusage:
	ms.assert.Equal(cert.KeyUsage, newCert.KeyUsage)
	// Check ExtKeyUsage
	ms.assert.Equal(cert.ExtKeyUsage, newCert.ExtKeyUsage)
	// Check DNSNames
	ms.assert.Equal(cert.DNSNames, newCert.DNSNames)
	ms.assert.Equal(cert.IPAddresses, newCert.IPAddresses)
	// Check Signature
	ms.assert.Nil(ms.coreServer.cert.CheckSignature(newCert.SignatureAlgorithm, newCert.RawTBSCertificate, newCert.Signature))
	// Check cert-chain
	pemRootCA := resp.GetParameters().Env["ROOT_CA"]
	ms.assert.NotNil(pemRootCA)
	p, _ = pem.Decode([]byte(pemRootCA))
	ms.assert.NotNil(p)
	rootCA, err := x509.ParseCertificate(p.Bytes)
	ms.assert.Nil(err, "cannot parse rootCA: %v", err)
	roots := x509.NewCertPool()
	roots.AddCert(rootCA)
	opts := x509.VerifyOptions{
		Roots:         roots,
		CurrentTime:   time.Now(),
		DNSName:       "localhost",
		Intermediates: x509.NewCertPool(),
		KeyUsages:     newCert.ExtKeyUsage,
	}
	_, err = newCert.Verify(opts)
	ms.assert.Nil(err, "failed to verify new certificate: %v", err)
}

func (ms *marbleSpawner) newMarbleAsync(marbleType string, infraName string, shouldSucceed bool) {
	ms.wg.Add(1)
	go func() {
		ms.newMarble(marbleType, infraName, shouldSucceed)
		ms.wg.Done()
	}()
}
