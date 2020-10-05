package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/rpc"
	"github.com/edgelesssys/coordinator/test"
	"github.com/edgelesssys/coordinator/util"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

var manifest core.Manifest

func TestMain(m *testing.M) {
	if err := json.Unmarshal([]byte(test.ManifestJSON), &manifest); err != nil {
		log.Fatalln(err)
	}
}
func TestQuote(t *testing.T) {
	assert := assert.New(t)
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := core.NewMockSealer()
	c, err := core.NewCore("edgeless", []string{"localhost"}, validator, issuer, sealer)
	if err != nil {
		panic(err)
	}

	mux := CreateServeMux(c)

	req := httptest.NewRequest(http.MethodGet, "/quote", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)
	assert.Equal(http.StatusOK, w.Code)

}

func TestManifest(t *testing.T) {
	assert := assert.New(t)
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := core.NewMockSealer()
	c, err := core.NewCore("edgeless", []string{"localhost"}, validator, issuer, sealer)
	if err != nil {
		panic(err)
	}

	mux := CreateServeMux(c)

	//set manifest
	req := httptest.NewRequest(http.MethodPost, "/manifest", bytes.NewReader([]byte(test.ManifestJSON)))

	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)
	resp := w.Result()
	assert.Equal(http.StatusOK, resp.StatusCode)

	//get manifest signature
	req = httptest.NewRequest(http.MethodGet, "/manifest", nil)

	w = httptest.NewRecorder()

	mux.ServeHTTP(w, req)
	resp = w.Result()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	assert.Equal(http.StatusOK, resp.StatusCode)
	assert.Contains(string(b), "{\"ManifestSignature\":")

	//try set manifest again, should fail
	req = httptest.NewRequest(http.MethodPost, "/manifest", bytes.NewReader([]byte(test.ManifestJSON)))
	w = httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	resp = w.Result()

	b, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	assert.Equal(http.StatusBadRequest, resp.StatusCode)
	assert.Equal("server is not in expected state\n", string(b))
}

func TestMarbleServer(t *testing.T) {
	assert := assert.New(t)
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()
	sealer := core.NewMockSealer()
	c, err := core.NewCore("edgeless", []string{"localhost"}, validator, issuer, sealer)
	if err != nil {
		panic(err)
	}

	mux := CreateServeMux(c)
	clientServerTLSConfig, err := c.GetTLSConfig()
	if err != nil {
		panic(err)
	}
	clientServerAddr := "127.0.0.1:25555"
	go RunClientServer(mux, clientServerAddr, clientServerTLSConfig)

	addrChan := make(chan string)
	errChan := make(chan error)
	marbleServerAddr := "127.0.0.1:25554"
	go RunMarbleServer(c, marbleServerAddr, addrChan, errChan)

	// try to activate marble before setting the manifest
	_, err = activateMarble(marbleServerAddr, "backend_first", issuer, validator)
	assert.NotNil(err, "expected error, but got nil")

	//set manifest
	err = setManifest([]byte(test.ManifestJSON), clientServerAddr)
	assert.Equal(err, nil, err)

	// activate marble
	_, err = activateMarble(marbleServerAddr, "backend_first", issuer, validator)
	assert.Nil(err, err)

}

func setManifest(manifest []byte, clientServerAddr string) error {
	// Use ClientAPI to set Manifest
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{Transport: tr}
	clientAPIURL := url.URL{
		Scheme: "https",
		Host:   clientServerAddr,
		Path:   "manifest",
	}

	resp, err := client.Post(clientAPIURL.String(), "application/json", bytes.NewBuffer(manifest))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected %v, but /manifest returned %v: %v", http.StatusOK, resp.Status, string(body))
	}
	return nil
}

func activateMarble(marbleServerAddr, marbleType string, issuer *quote.MockIssuer, validator *quote.MockValidator) (*rpc.ActivationResp, error) {
	// create certificate and CSR
	certTLS, cert, csr, privk, err := util.GenerateMarbleCredentials()
	if err != nil {
		return nil, err
	}

	// create mock quote using values from the manifest
	quote, err := issuer.Issue(cert)
	if err != nil {
		return nil, err
	}
	marble, _ := manifest.Marbles[marbleType]
	pkg, _ := manifest.Packages[marble.Package]
	infra, _ := manifest.Infrastructures["azure"]
	validator.AddValidQuote(quote, cert, pkg, infra)

	tlsCredentials, err := util.LoadTLSCredentials(certTLS, privk)
	if err != nil {
		return nil, err
	}

	// initiate grpc connection to Coordinator
	cc, err := grpc.Dial(marbleServerAddr, grpc.WithTransportCredentials(tlsCredentials))

	if err != nil {
		return nil, err
	}
	defer cc.Close()

	// authenticate with Coordinator
	req := &rpc.ActivationReq{
		CSR:        csr,
		MarbleType: marbleType,
		Quote:      quote,
		UUID:       uuid.New().String(),
	}
	c := rpc.NewMarbleClient(cc)
	return c.Activate(context.Background(), req)
}
