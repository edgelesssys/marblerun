/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	libMarble "github.com/edgelesssys/ego/marble"
	"github.com/edgelesssys/marblerun/coordinator/clientapi"
	"github.com/edgelesssys/marblerun/coordinator/distributor"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/edgelesssys/marblerun/test"
	"github.com/edgelesssys/marblerun/util"
	"github.com/google/uuid"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestCertificateVerify(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// parse manifest
	var manifest manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.ManifestJSON), &manifest))

	zapLogger := zaptest.NewLogger(t)

	// create core
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	stor := stdstore.New(&seal.MockSealer{}, stubEnabler{}, afero.NewMemMapFs(), "", zapLogger)
	recovery := recovery.New(stor, zapLogger)
	coreServer, err := NewCore([]string{"localhost"}, validator, issuer, stor, recovery, zapLogger, nil, nil)
	require.NoError(err)
	require.NotNil(coreServer)

	// set manifest
	clientAPI, err := clientapi.New(stor, coreServer.recovery, coreServer, &distributor.Stub{}, stubEnabler{}, zapLogger)
	require.NoError(err)
	_, err = clientAPI.SetManifest(context.Background(), []byte(test.ManifestJSON))
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

	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: tlsInfo,
	})

	resp, err := coreServer.Activate(ctx, &rpc.ActivationReq{
		CSR:        csr,
		MarbleType: marbleType,
		Quote:      quote,
		UUID:       uuid.New().String(),
	})

	assert.NoError(err, "Activate failed: %s", err)
	assert.NotNil(resp)

	// Get marble credentials
	params := resp.GetParameters()
	marbleKeyPEM, _ := pem.Decode(params.Env[libMarble.MarbleEnvironmentPrivateKey])
	require.NotNil(marbleKeyPEM)
	marbleKey, err := x509.ParsePKCS8PrivateKey(marbleKeyPEM.Bytes)
	require.NoError(err)
	leafCertPEM, rest := pem.Decode(params.Env[libMarble.MarbleEnvironmentCertificateChain])
	require.NotNil(leafCertPEM)
	require.NotEmpty(rest)
	leafCert, err := x509.ParseCertificate(leafCertPEM.Bytes)
	require.NoError(err)
	marbleRootPEM, rest := pem.Decode(rest)
	require.NotNil(marbleRootPEM)
	require.Empty(rest)

	// Verify cert-chain
	roots := x509.NewCertPool()
	assert.True(roots.AppendCertsFromPEM(pem.EncodeToMemory(marbleRootPEM)))
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	_, err = leafCert.Verify(opts)
	assert.NoError(err, "failed to verify certificate with Go: %s", err)

	// Verify certificate uses the correct public key
	leafPublicKey, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
	require.True(ok)
	marblePrivateKey, ok := marbleKey.(*ecdsa.PrivateKey)
	require.True(ok)
	assert.True(leafPublicKey.Equal(&marblePrivateKey.PublicKey), "public key mismatch")
}
