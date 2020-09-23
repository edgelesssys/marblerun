package core

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/stretchr/testify/assert"
)

func mustSetup() (*Core, *Manifest) {
	var manifest Manifest
	err := json.Unmarshal([]byte(manifestJSON), &manifest)
	if err != nil {
		panic(err)
	}

	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	tempDir, err := ioutil.TempDir("/tmp", "edg_coordinator_*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tempDir)
	mockKey := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	c, err := NewCore("edgeless", validator, issuer, tempDir, mockKey)
	if err != nil {
		panic(err)
	}
	return c, &manifest
}
func TestGetManifestSignature(t *testing.T) {
	assert := assert.New(t)

	c, _ := mustSetup()

	err := c.SetManifest(context.TODO(), []byte(manifestJSON))
	assert.Nil(err)

	sig := c.GetManifestSignature(context.TODO())
	expectedHash := sha256.Sum256([]byte(manifestJSON))
	assert.Equal(expectedHash[:], sig)

}

func TestSetManifest(t *testing.T) {
	assert := assert.New(t)

	c, manifest := mustSetup()
	err := c.SetManifest(context.TODO(), []byte(manifestJSON))

	assert.Nil(err, "SetManifest should succed on first try")
	assert.Equal(*manifest, c.manifest, "Manifest should be set correctly")
	err = c.SetManifest(context.TODO(), []byte(manifestJSON))
	assert.NotNil(err, "SetManifest should fail on the second try")
	assert.Equal(*manifest, c.manifest, "Manifest should still be set correctly")
	err = c.SetManifest(context.TODO(), []byte(manifestJSON)[:len(manifestJSON)-1])
	assert.NotNil(err, "SetManifest should fail on broken json")
	assert.Equal(*manifest, c.manifest, "Manifest should still be set correctly")

	//use new core
	c, _ = mustSetup()
	assert.NotNil(c.SetManifest(context.TODO(), []byte(manifestJSON)[:len(manifestJSON)-1]), "SetManifest should fail on broken json")
	c, _ = mustSetup()
	assert.NotNil(c.SetManifest(context.TODO(), []byte("")), "empty string should not be accepted")
	err = c.SetManifest(context.TODO(), []byte(manifestJSON))
	assert.Nil(err, "SetManifest should succed after failed tries")
	assert.Equal(*manifest, c.manifest, "Manifest should be set correctly")
}

func TestGetCertQuote(t *testing.T) {
	assert := assert.New(t)

	c, _ := mustSetup()

	cert, _, err := c.GetCertQuote(context.TODO())
	assert.Nil(err, "GetCertQuote should not fail (without manifest)")

	c.SetManifest(context.TODO(), []byte(manifestJSON))
	_, _, err = c.GetCertQuote(context.TODO())
	assert.Nil(err, "GetCertQuote should not fail (with manifest)")
	assert.Contains(cert, "-----BEGIN Certificate-----", "simple format check")
	//todo check quote

}
