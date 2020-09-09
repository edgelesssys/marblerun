package core

import (
	"context"
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
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestMarbleAPI(t *testing.T) {
	assert := assert.New(t)

	// parse manifest
	var manifest Manifest
	err := json.Unmarshal([]byte(manifestJSON), &manifest)
	assert.Nil(err)

	// create core
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	coreServer, err := NewCore("edgeless", validator, issuer)
	assert.NotNil(coreServer)
	assert.Nil(err)

	spawner := marbleSpawner{
		assert:    assert,
		issuer:    issuer,
		validator: validator,
		manifest:  manifest,
	}

	// try to activate first backend marble prematurely before manifest is set
	spawner.newMarble(coreServer, "backend_first", "Azure", false)

	// set manifest
	assert.Nil(coreServer.SetManifest(context.TODO(), []byte(manifestJSON)))

	// activate first backend
	spawner.newMarble(coreServer, "backend_first", "Azure", true)

	// try to activate another first backend
	spawner.newMarble(coreServer, "backend_first", "Azure", false)

	// activate 10 other backend
	pickInfra := func(i int) string {
		if i&1 == 0 {
			return "Azure"
		} else {
			return "Alibaba"
		}
	}
	for i := 0; i < 10; i++ {
		spawner.newMarble(coreServer, "backend_other", pickInfra(i), true)
	}

	// activate 10 frontend
	for i := 0; i < 10; i++ {
		spawner.newMarble(coreServer, "frontend", pickInfra(i), true)
	}
}

type marbleSpawner struct {
	manifest   Manifest
	validator  *quote.MockValidator
	issuer     quote.Issuer
	serverAddr string
	assert     *assert.Assertions
}

func (ms marbleSpawner) newMarble(coreServer *Core, marbleType string, infraName string, shouldSucceed bool) {
	// create certificate and CSR
	certTLS, cert, csr, err := generateMarbleCredentials()
	ms.assert.Nil(err)
	ms.assert.NotNil(cert)
	ms.assert.NotNil(csr)

	// create mock quote using values from the manifest
	quote, err := ms.issuer.Issue(cert)
	ms.assert.NotNil(quote)
	ms.assert.Nil(err)
	marble, ok := ms.manifest.Marbles[marbleType]
	ms.assert.True(ok)
	pkg, ok := ms.manifest.Packages[marble.Package]
	ms.assert.True(ok)
	infra, ok := ms.manifest.Infrastructures[infraName]
	ms.assert.True(ok)
	ms.validator.AddValidQuote(quote, cert, pkg, infra)

	tlsInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{certTLS},
		},
	}

	ctx := peer.NewContext(context.TODO(), &peer.Peer{
		AuthInfo: tlsInfo,
	})

	resp, err := coreServer.Activate(ctx, &rpc.ActivationReq{
		CSR:        csr,
		MarbleType: marbleType,
		Quote:      quote,
	})

	if !shouldSucceed {
		ms.assert.NotNil(err)
		ms.assert.Nil(resp)
		return
	}
	ms.assert.Nil(err, "Activate failed: %v", err)
	ms.assert.NotNil(resp)

	// validate response
	params := resp.GetParameters()
	ms.assert.Equal(marble.Parameters.Files, params.Files)
	ms.assert.Equal(marble.Parameters.Env, params.Env)
	ms.assert.Equal(marble.Parameters.Argv, params.Argv)

	newCert, err := x509.ParseCertificate(resp.GetCertificate())
	ms.assert.Nil(err)
	ms.assert.Equal(coordinatorName, newCert.Issuer.CommonName)
	// TODO: properly verify issued certificate
}

func generateMarbleCredentials() (certTLS *x509.Certificate, cert []byte, csr []byte, err error) {
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

	certTLS, err = x509.ParseCertificate(cert)
	if err != nil {
		return
	}

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
