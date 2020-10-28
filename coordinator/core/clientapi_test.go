package core

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/edgelesssys/coordinator/test"
	"github.com/stretchr/testify/assert"
)

func mustSetup() (*Core, *Manifest) {
	var manifest Manifest
	err := json.Unmarshal([]byte(test.ManifestJSON), &manifest)
	if err != nil {
		panic(err)
	}
	return NewCoreWithMocks(), &manifest
}

func TestGetManifestSignature(t *testing.T) {
	assert := assert.New(t)

	c, _ := mustSetup()

	err := c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	assert.Nil(err)

	sig := c.GetManifestSignature(context.TODO())
	expectedHash := sha256.Sum256([]byte(test.ManifestJSON))
	assert.Equal(expectedHash[:], sig)

}

func TestSetManifest(t *testing.T) {
	assert := assert.New(t)

	c, manifest := mustSetup()
	err := c.SetManifest(context.TODO(), []byte(test.ManifestJSON))

	assert.Nil(err, "SetManifest should succed on first try")
	assert.Equal(*manifest, c.manifest, "Manifest should be set correctly")
	err = c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	assert.NotNil(err, "SetManifest should fail on the second try")
	assert.Equal(*manifest, c.manifest, "Manifest should still be set correctly")
	err = c.SetManifest(context.TODO(), []byte(test.ManifestJSON)[:len(test.ManifestJSON)-1])
	assert.NotNil(err, "SetManifest should fail on broken json")
	assert.Equal(*manifest, c.manifest, "Manifest should still be set correctly")

	//use new core
	c, _ = mustSetup()
	assert.NotNil(c.SetManifest(context.TODO(), []byte(test.ManifestJSON)[:len(test.ManifestJSON)-1]), "SetManifest should fail on broken json")
	c, _ = mustSetup()
	assert.NotNil(c.SetManifest(context.TODO(), []byte("")), "empty string should not be accepted")
	err = c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	assert.Nil(err, "SetManifest should succed after failed tries")
	assert.Equal(*manifest, c.manifest, "Manifest should be set correctly")

	//try setting manifest with unallowed marble package, but propper json
	c, _ = mustSetup()
	//get any element of the map
	for _, marble := range manifest.Marbles {
		marble.Package = "foo"
		manifest.Marbles["bar"] = marble
		break
	}
	modRawManifest, _ := json.Marshal(manifest)
	err = c.SetManifest(context.TODO(), modRawManifest)
	assert.Equal("Manifest does not contain marble package foo", err.Error())

}

func TestGetCertQuote(t *testing.T) {
	assert := assert.New(t)

	c, _ := mustSetup()

	cert, _, err := c.GetCertQuote(context.TODO())
	assert.Nil(err, "GetCertQuote should not fail (without manifest)")

	c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	_, _, err = c.GetCertQuote(context.TODO())
	assert.Nil(err, "GetCertQuote should not fail (with manifest)")
	assert.Contains(cert, "-----BEGIN CERTIFICATE-----", "simple format check")
	//todo check quote

}
