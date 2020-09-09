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
	assert.Equal(sha256.Sum256([]byte(manifestJSON)), sig)

}
