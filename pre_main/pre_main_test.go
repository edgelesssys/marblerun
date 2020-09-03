package premain

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"
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

func TestLogic(t *testing.T) {
	assert := assert.New(t)

	// parse manifest
	var manifest core.Manifest
	err := json.Unmarshal([]byte(manifestMeshAPIJSON), &manifest)
	assert.Nil(err)
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()

	// create core and run gRPC server
	orgName := "edgless"
	commonName := "Coordinator" // TODO: core does not export this, for now just use it hardcoded
	coordinator, err := core.NewCore(orgName, validator, issuer)
	assert.NotNil(coordinator)
	assert.Nil(err)

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

	// set env variables
	err = os.Setenv(edgCoordinatorAddr, grpcAddr)
	assert.Nil(err)
	err = os.Setenv(edgMarbleID, "001")
	assert.Nil(err)
	err = os.Setenv(edgMarbleType, "backend")
	assert.Nil(err)

	// create Authenticator
	a, err := newAuthenticator("Edgeless Systems GmbH", "Marble", issuer)
	assert.Nil(err)

	// create mock quote using values from the manifest
	marbleType := "backend_first"
	infraName := "Azure"
	quote, err := issuer.Issue(a.initCert.Raw)
	assert.NotNil(quote)
	assert.Nil(err)
	marble, ok := manifest.Marbles[marbleType]
	assert.True(ok)
	pkg, ok := manifest.Packages[marble.Package]
	assert.True(ok)
	infra, ok := manifest.Infrastructures[infraName]
	assert.True(ok)
	validator.AddValidQuote(quote, a.initCert.Raw, pkg, infra)

	// initiate grpc connection to Coordinator
	tlsCredentials, err := loadTLSCredentials(a)
	assert.Nil(err)
	cc, err := grpc.Dial(grpcAddr, grpc.WithTransportCredentials(tlsCredentials))
	assert.Nil(err)

	defer cc.Close()

	// generate CSR
	err = a.generateCSR()
	assert.Nil(err)

	// authenticate with Coordinator
	c := rpc.NewMarbleClient(cc)
	req := &rpc.ActivationReq{
		CSR:        a.csr.Raw,
		MarbleType: marbleType,
		Quote:      a.quote,
	}

	activiationResp, err := c.Activate(context.Background(), req)
	assert.Nil(err)
	newCert, err := x509.ParseCertificate(activiationResp.GetCertificate())
	assert.Nil(err)
	a.marbleCert = newCert
	a.params = activiationResp.GetParameters()

	assert.Equal(marble.Parameters.Files, a.params.Files)
	assert.Equal(marble.Parameters.Env, a.params.Env)
	assert.Equal(marble.Parameters.Argv, a.params.Argv)

	assert.Equal(a.marbleCert.Issuer.CommonName, commonName)
	assert.Equal(a.marbleCert.Issuer.Organization[0], orgName)
	// commonName gets overwritten
	// assert.Equal(a.marbleCert.Subject.CommonName, a.commonName)
	assert.Equal(a.marbleCert.Subject.Organization[0], a.orgName)
	assert.Equal(a.marbleCert.PublicKey, a.pubk)
}
