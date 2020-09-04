package core

import (
	"encoding/json"
	"testing"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
)

const manifestJSON string = `{
	"Packages": {
		"backend": {
			"UniqueID": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],
			"Debug": false
		},
		"frontend": {
			"SignerID": [31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0],
			"ProductID": 44,
			"SecurityVersion": 3,
			"Debug": true
		}
	},
	"Infrastructures": {
		"Azure": {
			"QESVN": 2,
			"PCESVN": 3,
			"CPUSVN": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
			"RootCA": [3,3,3]
		},
		"Alibaba": {
			"QESVN": 2,
			"PCESVN": 4,
			"CPUSVN": [15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0],
			"RootCA": [4,4,4]
		}
	},
	"Marbles": {
		"backend_first": {
			"Package": "backend",
			"MaxActivations": 1,
			"Parameters": {
				"Files": {
					"/abc/defg.txt": [7,7,7],
					"/ghi/jkl.mno": [8,8,8]
				},
				"Env": {
					"IS_FIRST": "true"
				},
				"Argv": [
					"--first",
					"serve"
				]
			}
		},
		"backend_other": {
			"Package": "backend",
			"Parameters": {
				"Argv": [
					"serve"
				]
			}
		},
		"frontend": {
			"Package": "frontend"
		}
	},
	"Clients": {
		"owner": [9,9,9]
	}
}`

func TestCore(t *testing.T) {
	assert := assert.New(t)

	// parse manifest
	var manifest Manifest
	err := json.Unmarshal([]byte(manifestJSON), &manifest)
	assert.Nil(err)

	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()

	c, err := NewCore("edgeless", validator, issuer)
	assert.NotNil(c)
	assert.Nil(err)
	assert.Equal(acceptingManifest, c.state)
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

	// try to set broken manifest
	assert.NotNil(c.SetManifest(context.TODO(), []byte(manifestJSON)[:len(manifestJSON)-1]))

	// set manifest
	assert.Nil(c.SetManifest(context.TODO(), []byte(manifestJSON)))

	// set manifest a second time
	assert.NotNil(c.SetManifest(context.TODO(), []byte(manifestJSON)))
}
