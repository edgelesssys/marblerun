// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// +build openssl_test

package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"testing"

	libMarble "github.com/edgelesssys/ego/marble"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/test"
	"github.com/edgelesssys/marblerun/util"
	"github.com/google/uuid"
	"github.com/spacemonkeygo/openssl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestOpenSSLVerify(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// parse manifest
	var manifest manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.ManifestJSON), &manifest))

	// setup mock zaplogger which can be passed to Core
	zapLogger, err := zap.NewDevelopment()
	require.NoError(err)
	defer zapLogger.Sync()

	// create core
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &seal.MockSealer{}
	recovery := recovery.NewSinglePartyRecovery()
	coreServer, err := NewCore([]string{"localhost"}, validator, issuer, sealer, recovery, zapLogger, nil, nil)
	require.NoError(err)
	require.NotNil(coreServer)

	// set manifest
	_, err = coreServer.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	require.NoError(err)

	// create marble
	marbleType := "backendFirst"
	infraName := "Azure"
	cert, csr, _ := util.MustGenerateTestMarbleCredentials()
	// create mock quote using values from the manifest
	quote, err := issuer.Issue(cert.Raw)
	assert.NotNil(quote)
	assert.Nil(err)
	marble, ok := manifest.Marbles[marbleType]
	assert.True(ok)
	pkg, ok := manifest.Packages[marble.Package]
	assert.True(ok)
	infra, ok := manifest.Infrastructures[infraName]
	assert.True(ok)
	validator.AddValidQuote(quote, cert.Raw, pkg, infra)

	tlsInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		},
	}

	ctx := peer.NewContext(context.TODO(), &peer.Peer{
		AuthInfo: tlsInfo,
	})

	resp, err := coreServer.Activate(ctx, &rpc.ActivationReq{
		CSR:        csr,
		MarbleType: marbleType,
		Quote:      quote,
		UUID:       uuid.New().String(),
	})

	assert.NoError(err, "Activate failed: %v", err)
	assert.NotNil(resp)

	// Get marble credentials
	params := resp.GetParameters()
	pMarbleKey, _ := pem.Decode([]byte(params.Env[libMarble.MarbleEnvironmentPrivateKey]))
	require.NotNil(pMarbleKey)
	pLeaf, rest := pem.Decode([]byte(params.Env[libMarble.MarbleEnvironmentCertificateChain]))
	require.NotNil(pLeaf)
	require.NotEmpty(rest)
	pMarbleRoot, rest := pem.Decode(rest)
	require.NotNil(pMarbleRoot)
	require.Empty(rest)

	// Verify cert-chain with OpenSSL
	openSSLCtx, err := openssl.NewCtx()
	require.NoError(err)
	certStore := openSSLCtx.GetCertificateStore()
	rootCert, err := openssl.LoadCertificateFromPEM(pem.EncodeToMemory(pMarbleRoot))
	require.NoError(err)
	leafCert, err := openssl.LoadCertificateFromPEM(pem.EncodeToMemory(pLeaf))
	require.NoError(err)
	privKey, err := openssl.LoadPrivateKeyFromPEM(pem.EncodeToMemory(pMarbleKey))
	require.NoError(err)
	require.NoError(certStore.AddCertificate(rootCert))
	require.NoError(openSSLCtx.AddChainCertificate(rootCert))
	require.NoError(openSSLCtx.UseCertificate(leafCert))
	require.NoError(openSSLCtx.UsePrivateKey(privKey))
	openSSLCtx.SetVerifyMode(openssl.VerifyPeer)

	server, client := net.Pipe()
	go func() {
		sslServer, err := openssl.Server(server, openSSLCtx)
		require.NoError(err)
		assert.NoError(sslServer.Handshake())
		server.Close()
	}()
	sslClient, err := openssl.Client(client, openSSLCtx)
	require.NoError(err)
	assert.NoError(sslClient.Handshake())
	verifyResult := sslClient.VerifyResult()
	assert.Equal(openssl.Ok, verifyResult, "failed to verify certificate with openssl: %v", verifyResult)
}
