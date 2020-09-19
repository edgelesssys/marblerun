package core

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/stretchr/testify/assert"
)

func getSetup() (*Core, *Manifest, error) {

	var manifest Manifest
	err := json.Unmarshal([]byte(manifestJSON), &manifest)
	if err != nil {
		return nil, nil, err
	}

	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()

	c, err := NewCore("edgeless", validator, issuer)

	return c, &manifest, nil

}
func TestGetManifestSignature(t *testing.T) {
	assert := assert.New(t)

	c, _, err := getSetup()
	if err != nil {
		panic(err)
	}
	err = c.SetManifest(context.TODO(), []byte(manifestJSON))
	if err != nil {
		panic(err)
	}

	sig, err := c.GetManifestSignature(context.TODO())
	assert.Nil(err)
	expectedHash := sha256.Sum256([]byte(manifestJSON))
	assert.Equal(expectedHash[:], sig)

}

func TestSetManifest(t *testing.T) {
	assert := assert.New(t)

	c, manifest, err := getSetup()
	if err != nil {
		panic(err)
	}
	err = c.SetManifest(context.TODO(), []byte(manifestJSON))

	assert.Nil(err, "SetManifest should succed on first try")
	assert.Equal(*manifest, c.manifest, "Manifest should be set correctly")
	err = c.SetManifest(context.TODO(), []byte(manifestJSON))
	assert.NotNil(err, "SetManifest should fail on the second try")
	assert.Equal(*manifest, c.manifest, "Manifest should still be set correctly")
	err = c.SetManifest(context.TODO(), []byte(manifestJSON)[:len(manifestJSON)-1])
	assert.NotNil(err, "SetManifest should fail on broken json")
	assert.Equal(*manifest, c.manifest, "Manifest should still be set correctly")

	//use new core
	c, _, err = getSetup()
	assert.NotNil(c.SetManifest(context.TODO(), []byte(manifestJSON)[:len(manifestJSON)-1]), "SetManifest should fail on broken json")
	c, _, err = getSetup()
	assert.NotNil(c.SetManifest(context.TODO(), []byte("")), "empty string should not be accepted")
	err = c.SetManifest(context.TODO(), []byte(manifestJSON))
	assert.Nil(err, "SetManifest should succed after failed tries")
	assert.Equal(*manifest, c.manifest, "Manifest should be set correctly")
}

func TestGetCertQuote(t *testing.T) {
	assert := assert.New(t)

	c, _, err := getSetup()
	if err != nil {
		panic(err)
	}
	cert, _, err := c.GetCertQuote(context.TODO())
	assert.Nil(err, "GetCertQuote should not fail (without manifest)")

	c.SetManifest(context.TODO(), []byte(manifestJSON))
	_, _, err = c.GetCertQuote(context.TODO())
	assert.Nil(err, "GetCertQuote should not fail (with manifest)")
	assert.Contains(cert, "-----BEGIN Certificate-----", "simple format check")
	//todo check quote

}
