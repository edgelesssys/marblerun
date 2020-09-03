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

const manifestMeshAPIJSON string = `{
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
	err := json.Unmarshal([]byte(manifestMeshAPIJSON), &manifest)
	assert.Nil(err, err)
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()

	// create core and run gRPC server
	coordinator, err := core.NewCore(orgName, validator, issuer)
	assert.NotNil(coordinator, "coordinator empty")
	assert.Nil(err, err)

	coordinator.SetManifest(context.TODO(), []byte(manifestMeshAPIJSON))

	// run mesh server
	var grpcAddr string
	addrChan := make(chan string)
	errChan := make(chan error)
	meshServerAddr := flag.String("ip", "localhost:0", "")
	go server.RunMeshServer(coordinator, *meshServerAddr, addrChan, errChan)
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

func (ns marbleSpawner) newMarble(marbleType string, infraName string, shouldSucceed bool) {
	// create authenticator
	a, err := newAuthenticator("Edgeless Systems GmbH", "Marble", ns.issuer)
	ns.assert.Nil(err, err)

	// create mock quote using values from the manifest
	quote, err := ns.issuer.Issue(a.initCert.Raw)
	ns.assert.NotNil(quote, "expected empty quote, but got: %v", quote)
	ns.assert.Nil(err, err)
	marble, ok := ns.manifest.Marbles[marbleType]
	ns.assert.True(ok, "marbleType '%v' does not exist", marbleType)
	pkg, ok := ns.manifest.Packages[marble.Package]
	ns.assert.True(ok, "Package '%v' does not exist", marble.Package)
	infra, ok := ns.manifest.Infrastructures[infraName]
	ns.assert.True(ok, "Infrastructure '%v' does not exist", infraName)
	ns.validator.AddValidQuote(quote, a.initCert.Raw, pkg, infra)

	// initiate grpc connection to Coordinator
	tlsCredentials, err := loadTLSCredentials(a)
	ns.assert.Nil(err, err)
	cc, err := grpc.Dial(ns.serverAddr, grpc.WithTransportCredentials(tlsCredentials))
	ns.assert.Nil(err, err)

	defer cc.Close()

	// generate CSR
	err = a.generateCSR()
	ns.assert.Nil(err, err)

	// authenticate with Coordinator
	c := rpc.NewMarbleClient(cc)
	req := &rpc.ActivationReq{
		CSR:        a.csr.Raw,
		MarbleType: marbleType,
		Quote:      a.quote,
	}
	activationResp, err := c.Activate(context.Background(), req)

	if !shouldSucceed {
		ns.assert.NotNil(err, err)
		ns.assert.Nil(activationResp, "expected empty activationResp, but got %v", activationResp)
		return
	}
	ns.assert.Nil(err, err)
	ns.assert.NotNil(activationResp, "activationResp empty, but no Error returned")
	newCert, err := x509.ParseCertificate(activationResp.GetCertificate())
	ns.assert.Nil(err, err)
	a.marbleCert = newCert
	a.params = activationResp.GetParameters()

	ns.assert.Equal(marble.Parameters.Files, a.params.Files, "expected equal: '%v' - '%v'", marble.Parameters.Files, a.params.Files)
	ns.assert.Equal(marble.Parameters.Env, a.params.Env, "expected equal: '%v' - '%v'", marble.Parameters.Env, a.params.Env)
	ns.assert.Equal(marble.Parameters.Argv, a.params.Argv, "expected equal: '%v' - '%v'", marble.Parameters.Argv, a.params.Argv)

	ns.assert.Equal(a.marbleCert.Issuer.CommonName, commonName, "expected equal: '%v' - '%v'", a.marbleCert.Issuer.CommonName, commonName)
	ns.assert.Equal(a.marbleCert.Issuer.Organization[0], orgName, "expected equal: '%v' - '%v'", a.marbleCert.Issuer.Organization[0], orgName)
	// commonName gets overwritten
	// assert.Equal(a.marbleCert.Subject.CommonName, a.commonName)
	ns.assert.Equal(a.marbleCert.Subject.Organization[0], a.orgName, "expected equal: '%v' - '%v'", a.marbleCert.Subject.Organization[0], a.orgName)
	ns.assert.Equal(a.marbleCert.PublicKey, a.pubk, "expected equal: '%v' - '%v'", a.marbleCert.PublicKey, a.pubk)
}
