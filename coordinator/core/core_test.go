package core

import (
	"crypto/sha256"
	"testing"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/test"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
)

func TestCore(t *testing.T) {
	assert := assert.New(t)

	c := NewCoreWithMocks()
	assert.Equal(stateAcceptingManifest, c.state)
	assert.Equal([]string{"edgeless"}, c.cert.Subject.Organization)
	assert.Equal(coordinatorName, c.cert.Subject.CommonName)

	// get quote
	quote, err := c.GetQuote(context.TODO())
	assert.NotNil(quote)
	assert.Nil(err)

	// get TLS certificate
	cert, err := c.GetTLSCertificate()
	assert.NotNil(cert)
	assert.Nil(err)

	//get TLS config
	config, err := c.GetTLSConfig()
	assert.NotNil(config)
	assert.Nil(err)

	// try to set broken manifest
	assert.NotNil(c.SetManifest(context.TODO(), []byte(test.ManifestJSON)[:len(test.ManifestJSON)-1]))

	// set manifest
	assert.Nil(c.SetManifest(context.TODO(), []byte(test.ManifestJSON)))

	// set manifest a second time
	assert.NotNil(c.SetManifest(context.TODO(), []byte(test.ManifestJSON)))
}

func TestSeal(t *testing.T) {
	assert := assert.New(t)

	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := NewMockSealer()

	// create Core
	c, err := NewCore("edgeless", []string{"localhost"}, validator, issuer, sealer)
	assert.NotNil(c)
	assert.Nil(err)
	// set manifest
	assert.Nil(c.SetManifest(context.TODO(), []byte(test.ManifestJSON)))
	// get quote
	quote, err := c.GetQuote(context.TODO())
	assert.NotNil(quote)
	assert.Nil(err)
	// get TLS certificate
	cert, err := c.GetTLSCertificate()
	assert.NotNil(cert)
	assert.Nil(err)
	//get Manifest Signature
	signature := c.GetManifestSignature(context.TODO())
	hash := sha256.Sum256(c.rawManifest)
	assert.Equal(hash[:], signature, "manifest signature is not correct")

	// check sealing
	c2, err := NewCore("edgeless", []string{"localhost"}, validator, issuer, sealer)
	assert.NotNil(c2)
	assert.Nil(err)
	assert.Equal(stateAcceptingMarbles, c2.state)

	quote2, err := c2.GetQuote(context.TODO())
	assert.NotNil(quote2)
	assert.Nil(err)
	assert.Equal(quote, quote2)

	cert2, err := c2.GetTLSCertificate()
	assert.NotNil(cert2)
	assert.Nil(err)
	assert.Equal(cert, cert2)

	assert.NotNil(c2.SetManifest(context.TODO(), []byte(test.ManifestJSON)))

	signature2 := c.GetManifestSignature(context.TODO())
	assert.Equal(signature, signature2, "manifest signature differs after restart")

}
