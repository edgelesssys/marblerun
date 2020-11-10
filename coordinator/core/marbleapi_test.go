// Copyright (c) Edgeless Systems GmbH.
// Licensed under the MIT License.

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

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/rpc"
	"github.com/edgelesssys/coordinator/test"
	"github.com/edgelesssys/coordinator/util"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestActivate(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// parse manifest
	var manifest Manifest
	require.NoError(json.Unmarshal([]byte(test.ManifestJSON), &manifest))

	// setup mock zaplogger which can be passed to Core
	zapLogger, err := zap.NewDevelopment()
	require.NoError(err)
	defer zapLogger.Sync()

	// create core
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &MockSealer{}
	coreServer, err := NewCore([]string{"localhost"}, validator, issuer, sealer, zapLogger)
	require.NoError(err)
	require.NotNil(coreServer)

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
	_, err = coreServer.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	require.NoError(err)

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
		ms.assert.Error(err)
		ms.assert.Nil(resp)
		return
	}
	ms.assert.NoError(err, "Activate failed: %v", err)
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
	p, _ := pem.Decode([]byte(params.Env["MARBLE_KEY"]))
	ms.assert.NotNil(p)

	// Validate Cert
	p, _ = pem.Decode([]byte(params.Env["MARBLE_CERT"]))
	ms.assert.NotNil(p)
	newCert, err := x509.ParseCertificate(p.Bytes)
	ms.assert.NoError(err)
	ms.assert.Equal(CoordinatorName, newCert.Issuer.CommonName)
	// Check CommonName
	_, err = uuid.Parse(newCert.Subject.CommonName)
	ms.assert.NoError(err, "cert.Subject.CommonName is not a valid UUID: %v", err)
	// Check KeyUusage:
	ms.assert.Equal(cert.KeyUsage, newCert.KeyUsage)
	// Check ExtKeyUsage
	ms.assert.Equal(cert.ExtKeyUsage, newCert.ExtKeyUsage)
	// Check DNSNames
	ms.assert.Equal(cert.DNSNames, newCert.DNSNames)
	ms.assert.Equal(cert.IPAddresses, newCert.IPAddresses)
	// Check Signature
	ms.assert.NoError(ms.coreServer.cert.CheckSignature(newCert.SignatureAlgorithm, newCert.RawTBSCertificate, newCert.Signature))

	// Check cert-chain
	roots := x509.NewCertPool()
	ms.assert.True(roots.AppendCertsFromPEM([]byte(params.Env["ROOT_CA"])), "cannot parse rootCA")
	opts := x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "localhost",
		KeyUsages: newCert.ExtKeyUsage,
	}
	_, err = newCert.Verify(opts)
	ms.assert.NoError(err, "failed to verify new certificate: %v", err)
}

func (ms *marbleSpawner) newMarbleAsync(marbleType string, infraName string, shouldSucceed bool) {
	ms.wg.Add(1)
	go func() {
		ms.newMarble(marbleType, infraName, shouldSucceed)
		ms.wg.Done()
	}()
}
