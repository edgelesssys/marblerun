package core

import (
	"context"
	"testing"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestCore(t *testing.T) {
	assert := assert.New(t)

	c := NewCoreWithMocks()
	assert.Equal(stateAcceptingManifest, c.state)
	assert.Equal(CoordinatorName, c.cert.Subject.CommonName)

	cert, err := c.GetTLSCertificate()
	assert.NoError(err)
	assert.NotNil(cert)

	config, err := c.GetTLSConfig()
	assert.NoError(err)
	assert.NotNil(config)

	manifest := []byte(test.ManifestJSON)
	// try to set broken manifest
	assert.Error(c.SetManifest(context.TODO(), manifest[:len(manifest)-1]))
	// set manifest
	assert.NoError(c.SetManifest(context.TODO(), manifest))
	// set manifest a second time
	assert.Error(c.SetManifest(context.TODO(), manifest))
}

func TestSeal(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// setup mock zaplogger which can be passed to Core
	zapLogger, err := zap.NewDevelopment()
	require.NoError(err)
	defer zapLogger.Sync()

	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := &MockSealer{}

	c, err := NewCore([]string{"localhost"}, validator, issuer, sealer, zapLogger)
	require.NoError(err)

	// Set manifest. This will seal the state.
	require.NoError(c.SetManifest(context.TODO(), []byte(test.ManifestJSON)))

	// Get certificate and signature.
	cert, err := c.GetTLSCertificate()
	assert.NoError(err)
	signature := c.GetManifestSignature(context.TODO())

	// Check sealing with a new core initialized with the sealed state.
	c2, err := NewCore([]string{"localhost"}, validator, issuer, sealer, zapLogger)
	require.NoError(err)
	assert.Equal(stateAcceptingMarbles, c2.state)

	cert2, err := c2.GetTLSCertificate()
	assert.NoError(err)
	assert.Equal(cert, cert2)

	assert.Error(c2.SetManifest(context.TODO(), []byte(test.ManifestJSON)))

	signature2 := c.GetManifestSignature(context.TODO())
	assert.Equal(signature, signature2, "manifest signature differs after restart")
}
