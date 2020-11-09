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
	if err := json.Unmarshal([]byte(test.ManifestJSON), &manifest); err != nil {
		panic(err)
	}
	return NewCoreWithMocks(), &manifest
}

func TestGetManifestSignature(t *testing.T) {
	assert := assert.New(t)

	c, _ := mustSetup()

	assert.NoError(c.SetManifest(context.TODO(), []byte(test.ManifestJSON)))

	sig := c.GetManifestSignature(context.TODO())
	expectedHash := sha256.Sum256([]byte(test.ManifestJSON))
	assert.Equal(expectedHash[:], sig)
}

func TestSetManifest(t *testing.T) {
	assert := assert.New(t)

	c, manifest := mustSetup()
	err := c.SetManifest(context.TODO(), []byte(test.ManifestJSON))

	assert.NoError(err, "SetManifest should succed on first try")
	assert.Equal(*manifest, c.manifest, "Manifest should be set correctly")
	err = c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	assert.Error(err, "SetManifest should fail on the second try")
	assert.Equal(*manifest, c.manifest, "Manifest should still be set correctly")
	err = c.SetManifest(context.TODO(), []byte(test.ManifestJSON)[:len(test.ManifestJSON)-1])
	assert.Error(err, "SetManifest should fail on broken json")
	assert.Equal(*manifest, c.manifest, "Manifest should still be set correctly")

	// use new core
	c, _ = mustSetup()
	assert.Error(c.SetManifest(context.TODO(), []byte(test.ManifestJSON)[:len(test.ManifestJSON)-1]), "SetManifest should fail on broken json")
	c, _ = mustSetup()
	assert.Error(c.SetManifest(context.TODO(), []byte("")), "empty string should not be accepted")
	assert.NoError(c.SetManifest(context.TODO(), []byte(test.ManifestJSON)), "SetManifest should succed after failed tries")
	assert.Equal(*manifest, c.manifest, "Manifest should be set correctly")

	// try setting manifest with unallowed marble package, but proper json
	c, _ = mustSetup()
	// get any element of the map
	for _, marble := range manifest.Marbles {
		marble.Package = "foo"
		manifest.Marbles["bar"] = marble
		break
	}
	modRawManifest, err := json.Marshal(manifest)
	assert.NoError(err)
	err = c.SetManifest(context.TODO(), modRawManifest)
	assert.Equal("manifest does not contain marble package foo", err.Error())
}

func TestGetCertQuote(t *testing.T) {
	assert := assert.New(t)

	c, _ := mustSetup()

	cert, _, err := c.GetCertQuote(context.TODO())
	assert.NoError(err, "GetCertQuote should not fail (without manifest)")
	assert.Contains(cert, "-----BEGIN CERTIFICATE-----", "simple format check")

	c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	_, _, err = c.GetCertQuote(context.TODO())
	assert.NoError(err, "GetCertQuote should not fail (with manifest)")
	//todo check quote
}
