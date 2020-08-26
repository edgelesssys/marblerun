package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/rpc"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestLogic(t *testing.T) {
	assert := assert.New(t)
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
		"Pods": {
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

	// parse manifest
	var manifest Manifest
	err := json.Unmarshal([]byte(manifestJSON), &manifest)
	assert.Nil(err)

	var clientServer rpc.ClientServer
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()

	// create core and run gRPC server
	var grpcAddr string
	{
		c, err := NewCore("edgeless", validator, issuer)
		assert.NotNil(c)
		assert.Nil(err)
		assert.Equal(acceptingManifest, c.state)
		assert.Equal([]string{"edgeless"}, c.cert.Subject.Organization)
		assert.Equal(coordinatorName, c.cert.Subject.CommonName)

		// run gRPC server on localhost
		addrChan := make(chan string)
		errChan := make(chan error)
		go RunGRPCServer(c, "localhost:0", addrChan, errChan)
		select {
		case err = <-errChan:
			assert.Fail("Failed to start gRPC server", err)
		case grpcAddr = <-addrChan:
		}

		clientServer = c
	}

	spawner := podSpawner{
		assert:     assert,
		issuer:     issuer,
		validator:  validator,
		serverAddr: grpcAddr,
		manifest:   manifest,
	}

	// get quote
	{
		quote, err := clientServer.GetQuote(context.TODO())
		assert.NotNil(quote)
		assert.Nil(err)
	}

	// try to activate first backend pod prematurely
	spawner.newPod("backend_first", "Azure", false)

	// try to set broken manifest
	assert.NotNil(clientServer.SetManifest(context.TODO(), []byte(manifestJSON)[:len(manifestJSON)-1]))

	// set manifest
	assert.Nil(clientServer.SetManifest(context.TODO(), []byte(manifestJSON)))

	// activate first backend
	spawner.newPod("backend_first", "Azure", true)

	// try to activate another first backend
	spawner.newPod("backend_first", "Azure", false)

	// activate 10 other backend
	pickInfra := func(i int) string {
		if i&1 == 0 {
			return "Azure"
		} else {
			return "Alibaba"
		}
	}
	for i := 0; i < 10; i++ {
		spawner.newPod("backend_other", pickInfra(i), true)
	}

	// activate 10 frontend
	for i := 0; i < 10; i++ {
		spawner.newPod("frontend", pickInfra(i), true)
	}
}

func generatePodCredentials() (certTLS *tls.Certificate, cert []byte, csr []byte, err error) {
	const orgName string = "Edgeless Systems GmbH"
	pubk, privk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	// create self-signed certificate for use in initial TLS connection
	notBefore := time.Now()
	notAfter := notBefore.Add(math.MaxInt64)

	serialNumber, err := generateSerial()
	if err != nil {
		return
	}
	templateCert := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{orgName},
			CommonName:   coordinatorName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: false,
		IsCA:                  true,
	}
	cert, err = x509.CreateCertificate(rand.Reader, &templateCert, &templateCert, pubk, privk)
	if err != nil {
		return
	}
	// create TLS certificate
	certTLS = tlsCertFromDER(cert, privk)
	// create CSR
	templateCSR := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{orgName},
		},
		PublicKey: pubk,
	}
	csr, err = x509.CreateCertificateRequest(rand.Reader, &templateCSR, privk)
	return
}

type podSpawner struct {
	manifest   Manifest
	validator  *quote.MockValidator
	issuer     quote.Issuer
	serverAddr string
	assert     *assert.Assertions
}

func (ns podSpawner) newPod(podType string, infraName string, shouldSucceed bool) {
	// create certificate and CSR
	certTLS, cert, csr, err := generatePodCredentials()
	ns.assert.Nil(err)
	ns.assert.NotNil(cert)
	ns.assert.NotNil(csr)

	// create mock quote using values from the manifest
	quote, err := ns.issuer.Issue(cert)
	ns.assert.NotNil(quote)
	ns.assert.Nil(err)
	pod, ok := ns.manifest.Pods[podType]
	ns.assert.True(ok)
	pkg, ok := ns.manifest.Packages[pod.Package]
	ns.assert.True(ok)
	infra, ok := ns.manifest.Infrastructures[infraName]
	ns.assert.True(ok)
	ns.validator.AddValidQuote(quote, cert, pkg, infra)

	// call Activate() over TLS
	tlsConfig := tls.Config{
		// NOTE: in our protocol it is not unsecure to skip server verification
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{*certTLS},
	}
	tlsCreds := credentials.NewTLS(&tlsConfig)
	conn, err := grpc.Dial(ns.serverAddr, grpc.WithTransportCredentials(tlsCreds))
	ns.assert.Nil(err)
	client := rpc.NewPodClient(conn)
	resp, err := client.Activate(context.TODO(), &rpc.ActivationReq{
		CSR:     csr,
		PodType: podType,
		Quote:   quote,
	})

	if !shouldSucceed {
		ns.assert.NotNil(err)
		ns.assert.Nil(resp)
		return
	}
	ns.assert.Nil(err)
	ns.assert.NotNil(resp)

	// validate response
	params := resp.GetParameters()
	ns.assert.Equal(pod.Parameters.Files, params.Files)
	ns.assert.Equal(pod.Parameters.Env, params.Env)
	ns.assert.Equal(pod.Parameters.Argv, params.Argv)

	newCert, err := x509.ParseCertificate(resp.GetCertificate())
	ns.assert.Nil(err)
	ns.assert.Equal(coordinatorName, newCert.Issuer.CommonName)
	// TODO: properly verify issued certificate
}
