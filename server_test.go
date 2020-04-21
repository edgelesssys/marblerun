package coordinator

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math"
	"testing"
	"time"

	"edgeless.systems/mesh/coordinator/rpc"

	"golang.org/x/net/context"

	"github.com/stretchr/testify/assert"
)

func generateNodeCredentials() (cert []byte, csr []byte, err error) {
	const orgName string = "Acme Inc."
	// create CSR for first TiKV node
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

func TestServer(t *testing.T) {
	var s *Server
	var err error

	t.Run("create server", func(t *testing.T) {
		s, err = NewServer("edgeless")
		assert.NotNil(t, s)
		assert.Nil(t, err)
		assert.Equal(t, s.state, acceptingManifest)
		assert.Equal(t, s.cert.Subject.Organization, []string{"edgeless"})
		assert.Equal(t, s.cert.Subject.CommonName, coordinatorName)
	})

	// t.Run("attempt to activate node prematurely", func(t *testing.T) {
	// 	s.Activate(context.TODO(), )
	// })

	const manifest string = `{
		"Packages": {
			"tikv": {
				"MREnclave": [1,2,3,4],
				"ISVProdID": 99,
				"MinISVSVN": 2
			},
			"tidb": {
				"MRSigner": [5,6,7,8,9,10],
				"ISVProdID": 44,
				"MinISVSVN": 3,
				"Attributes": [1,1,1,1]
			}
		},
		"Attestation": {
			"MinCPUSVN": [3,3,3],
			"RootCAs": {
				"Intel": [4,4,4],
				"Azure": [5,5,5]
			}
		},
		"Nodes": {
			"tikv_first": {
				"Package": "tikv",
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
			"tikv_other": {
				"Package": "tikv",
				"Parameters": {
					"Argv": [
						"serve"
					]
				}
			},
			"tidb": {
				"Package": "tidb"
			}
		},
		"Clients": {
			"owner": [9,9,9]
		}
		}`

	t.Run("attempt to set broken manifest", func(t *testing.T) {
		assert.NotNil(t, s.SetManifest(context.TODO(), []byte(manifest)[:len(manifest)-1]))
	})

	t.Run("set manifest", func(t *testing.T) {
		assert.Nil(t, s.SetManifest(context.TODO(), []byte(manifest)))
	})

	t.Run("activate first tikv", func(t *testing.T) {
		cert, csr, err := generateNodeCredentials()
		assert.Nil(t, err)
		assert.NotNil(t, cert, csr)

		req := rpc.ActivationReq{
			CSR:      csr,
			NodeType: "tikv_first",
			Quote:    []byte{1, 2, 3},
		}

		resp, err := s.Activate(context.TODO(), &req, cert)
		assert.Nil(t, err)
		assert.NotNil(t, resp)
	})

}
