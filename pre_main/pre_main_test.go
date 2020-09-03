package premain

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"testing"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/rpc"
	"github.com/edgelesssys/coordinator/coordinator/server"
	"google.golang.org/grpc"

	"github.com/stretchr/testify/assert"
)

const manifestJSON string = `{
	"Packages": {
		"backend": {
			"MREnclave": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],
			"MiscSelect": 1111111,
			"Attributes": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
		},
		"frontend": {
			"MRSigner": [31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0],
			"ISVProdID": 44,
			"ISVSVN": 3,
			"Attributes": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
			"MiscSelect": 1111111
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

const commonName string = "Coordinator" // TODO: core does not export this, for now just use it hardcoded

func TestLogic(t *testing.T) {
	assert := assert.New(t)

	// parse manifest
	var manifest core.Manifest
	err := json.Unmarshal([]byte(manifestJSON), &manifest)
	assert.Nil(err, err)
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()

	// create core and run gRPC server
	coordinator, err := core.NewCore(orgName, validator, issuer)
	assert.NotNil(coordinator, "coordinator empty")
	assert.Nil(err, err)

	coordinator.SetManifest(context.TODO(), []byte(manifestJSON))

	// run marble server
	var grpcAddr string
	addrChan := make(chan string)
	errChan := make(chan error)
	marbleServerAddr := flag.String("ip", "localhost:0", "")
	go server.RunMarbleServer(coordinator, *marbleServerAddr, addrChan, errChan)
	select {
	case err = <-errChan:
		fmt.Println("Failed to start gRPC server", err)
	case grpcAddr = <-addrChan:
		fmt.Println("start mesh server at", grpcAddr)
	}

	spawner := marbleSpawner{
		assert:     assert,
		issuer:     issuer,
		validator:  validator,
		manifest:   manifest,
		serverAddr: grpcAddr,
	}

	// activate first backend
	spawner.newMarble("backend_first", "Azure", true)

	// try to activate another first backend
	spawner.newMarble("backend_first", "Azure", false)

	// activate 10 other backend
	pickInfra := func(i int) string {
		if i&1 == 0 {
			return "Azure"
		}
		return "Alibaba"
	}
	for i := 0; i < 10; i++ {
		spawner.newMarble("backend_other", pickInfra(i), true)
	}

	// activate 10 frontend
	for i := 0; i < 10; i++ {
		spawner.newMarble("frontend", pickInfra(i), true)
	}

}

type marbleSpawner struct {
	manifest   core.Manifest
	validator  *quote.MockValidator
	issuer     quote.Issuer
	serverAddr string
	assert     *assert.Assertions
}

func (ms marbleSpawner) newMarble(marbleType string, infraName string, shouldSucceed bool) {
	// create authenticator
	a, err := newAuthenticator("Edgeless Systems GmbH", "Marble", ms.issuer)
	ms.assert.Nil(err, err)

	// create mock quote using values from the manifest
	quote, err := ms.issuer.Issue(a.initCert.Raw)
	ms.assert.NotNil(quote, "expected empty quote, but got: %v", quote)
	ms.assert.Nil(err, err)
	marble, ok := ms.manifest.Marbles[marbleType]
	ms.assert.True(ok, "marbleType '%v' does not exist", marbleType)
	pkg, ok := ms.manifest.Packages[marble.Package]
	ms.assert.True(ok, "Package '%v' does not exist", marble.Package)
	infra, ok := ms.manifest.Infrastructures[infraName]
	ms.assert.True(ok, "Infrastructure '%v' does not exist", infraName)
	ms.validator.AddValidQuote(quote, a.initCert.Raw, pkg, infra)

	// initiate grpc connection to Coordinator
	tlsCredentials, err := loadTLSCredentials(a)
	ms.assert.Nil(err, err)
	cc, err := grpc.Dial(ms.serverAddr, grpc.WithTransportCredentials(tlsCredentials))
	ms.assert.Nil(err, err)

	defer cc.Close()

	// generate CSR
	err = a.generateCSR()
	ms.assert.Nil(err, err)

	// authenticate with Coordinator
	c := rpc.NewMarbleClient(cc)
	req := &rpc.ActivationReq{
		CSR:        a.csr.Raw,
		MarbleType: marbleType,
		Quote:      a.quote,
	}
	activationResp, err := c.Activate(context.Background(), req)

	if !shouldSucceed {
		ms.assert.NotNil(err, err)
		ms.assert.Nil(activationResp, "expected empty activationResp, but got %v", activationResp)
		return
	}
	ms.assert.Nil(err, err)
	ms.assert.NotNil(activationResp, "activationResp empty, but no Error returned")
	newCert, err := x509.ParseCertificate(activationResp.GetCertificate())
	ms.assert.Nil(err, err)
	a.marbleCert = newCert
	a.params = activationResp.GetParameters()

	ms.assert.Equal(marble.Parameters.Files, a.params.Files, "expected equal: '%v' - '%v'", marble.Parameters.Files, a.params.Files)
	ms.assert.Equal(marble.Parameters.Env, a.params.Env, "expected equal: '%v' - '%v'", marble.Parameters.Env, a.params.Env)
	ms.assert.Equal(marble.Parameters.Argv, a.params.Argv, "expected equal: '%v' - '%v'", marble.Parameters.Argv, a.params.Argv)

	ms.assert.Equal(a.marbleCert.Issuer.CommonName, commonName, "expected equal: '%v' - '%v'", a.marbleCert.Issuer.CommonName, commonName)
	ms.assert.Equal(a.marbleCert.Issuer.Organization[0], orgName, "expected equal: '%v' - '%v'", a.marbleCert.Issuer.Organization[0], orgName)
	// commonName gets overwritten
	// assert.Equal(a.marbleCert.Subject.CommonName, a.commonName)
	ms.assert.Equal(a.marbleCert.Subject.Organization[0], a.orgName, "expected equal: '%v' - '%v'", a.marbleCert.Subject.Organization[0], a.orgName)
	ms.assert.Equal(a.marbleCert.PublicKey, a.pubk, "expected equal: '%v' - '%v'", a.marbleCert.PublicKey, a.pubk)
}
