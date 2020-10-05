package marble

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/coordinator/server"
	"github.com/edgelesssys/coordinator/marble/config"
	"github.com/edgelesssys/coordinator/test"
	"github.com/edgelesssys/coordinator/util"
	"github.com/google/uuid"
	"github.com/spf13/afero"

	"github.com/stretchr/testify/assert"
)

const coordinatorCommonName string = "Coordinator" // TODO: core does not export this, for now just use it hardcoded

const uuidFile string = "uuid"

var appFs afero.Fs

var sealKey []byte

func TestLogic(t *testing.T) {
	assert := assert.New(t)

	// parse manifest
	var manifest core.Manifest
	err := json.Unmarshal([]byte(test.ManifestJSON), &manifest)
	assert.Nil(err, err)
	validator := quote.NewMockValidator()
	issuer := quote.NewMockIssuer()

	// create core and run gRPC server
	sealer := core.NewMockSealer()
	coordinator, err := core.NewCore("Edgeless Systems GmbH", []string{"localhost"}, validator, issuer, sealer)
	assert.NotNil(coordinator, "coordinator empty")
	assert.Nil(err, err)

	coordinator.SetManifest(context.TODO(), []byte(test.ManifestJSON))

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

	// create MockFileHandler
	appFs = afero.NewMemMapFs()

	spawner := marbleSpawner{
		assert:     assert,
		issuer:     issuer,
		validator:  validator,
		manifest:   manifest,
		serverAddr: grpcAddr,
	}
	// activate first backend
	spawner.newMarble("backend_first", "Azure", false, true)

	// try to activate another first backend
	spawner.newMarble("backend_first", "Azure", false, false)

	// activate 10 other backend
	pickInfra := func(i int) string {
		if i&1 == 0 {
			return "Azure"
		}
		return "Alibaba"
	}
	pickUUID := func(i int) bool {
		return i&1 != 0
	}
	for i := 0; i < 10; i++ {
		spawner.newMarble("backend_other", pickInfra(i), pickUUID(i), true)
	}

	// activate 10 frontend
	for i := 0; i < 10; i++ {
		spawner.newMarble("frontend", pickInfra(i), pickUUID(i), true)
	}

}

type marbleSpawner struct {
	manifest   core.Manifest
	validator  *quote.MockValidator
	issuer     quote.Issuer
	serverAddr string
	assert     *assert.Assertions
}

func (ms marbleSpawner) newMarble(marbleType string, infraName string, reuseUUID bool, shouldSucceed bool) {
	// set env vars
	err := os.Setenv(config.EdgCoordinatorAddr, ms.serverAddr)
	ms.assert.Nil(err, "failed to set env variable: %v", err)
	err = os.Setenv(config.EdgMarbleType, marbleType)
	ms.assert.Nil(err, "failed to set env variable: %v", err)
	err = os.Setenv(config.EdgMarbleDNSNames, "backend_service,backend,localhost")
	ms.assert.Nil(err, "failed to set env variable: %v", err)

	if !reuseUUID {
		appFs.RemoveAll(uuidFile)
	}
	err = os.Setenv(config.EdgMarbleUUIDFile, uuidFile)
	ms.assert.Nil(err, "failed to set env variable: %v", err)

	// create mock args for preMain
	issuer := quote.NewMockIssuer()
	cert, privk, err := generateCert()
	ms.assert.Nil(err, "failed to generate cert: %v", err)
	quote, err := issuer.Issue(cert.Raw)
	ms.assert.Nil(err, "failed to generate quote: %v", err)

	// store quote in validator
	marble, ok := ms.manifest.Marbles[marbleType]
	ms.assert.True(ok, "marbleType '%v' does not exist", marbleType)
	pkg, ok := ms.manifest.Packages[marble.Package]
	ms.assert.True(ok, "Package '%v' does not exist", marble.Package)
	infra, ok := ms.manifest.Infrastructures[infraName]
	ms.assert.True(ok, "Infrastructure '%v' does not exist", infraName)
	ms.validator.AddValidQuote(quote, cert.Raw, pkg, infra)

	dummyMain := func(argc int, argv []string, env []string) int {
		// check argv
		ms.assert.Equal(len(marble.Parameters.Argv), argc)
		ms.assert.Equal(marble.Parameters.Argv, argv)

		// check env
		for key, value := range marble.Parameters.Env {
			readValue := util.MustGetenv(key)
			if !strings.Contains(value, "$$") {
				ms.assert.Equal(value, readValue, "%v env var differs from manifest", key)
			}
		}

		// check files
		for path, data := range marble.Parameters.Files {
			readContent, err := afero.ReadFile(appFs, path)
			ms.assert.Nil(err, "error reading file %v: %v", path, err)
			if !strings.Contains(data, "$$") {
				ms.assert.Equal(data, string(readContent), "content of file %v differs from manifest", path)
			}

		}
		// Validate SealKey
		pemSealKey := util.MustGetenv("SEAL_KEY")
		ms.assert.NotNil(pemSealKey)
		p, _ := pem.Decode([]byte(pemSealKey))
		ms.assert.NotNil(p)

		// Validate Marble Key
		pemMarbleKey := util.MustGetenv("MARBLE_KEY")
		ms.assert.NotNil(pemMarbleKey)
		p, _ = pem.Decode([]byte(pemMarbleKey))
		ms.assert.NotNil(p)

		// Validate Cert
		pemCert := util.MustGetenv("MARBLE_CERT")
		ms.assert.NotNil(pemCert)
		p, _ = pem.Decode([]byte(pemCert))
		ms.assert.NotNil(p)
		newCert, err := x509.ParseCertificate(p.Bytes)
		ms.assert.Nil(err)
		// Check cert-chain
		pemRootCA := util.MustGetenv("ROOT_CA")
		ms.assert.NotNil(pemRootCA)
		p, _ = pem.Decode([]byte(pemRootCA))
		ms.assert.NotNil(p)
		rootCA, err := x509.ParseCertificate(p.Bytes)
		ms.assert.Nil(err, "cannot parse rootCA: %v", err)
		roots := x509.NewCertPool()
		roots.AddCert(rootCA)
		opts := x509.VerifyOptions{
			Roots:         roots,
			CurrentTime:   time.Now(),
			DNSName:       "localhost",
			Intermediates: x509.NewCertPool(),
			KeyUsages:     newCert.ExtKeyUsage,
		}
		_, err = newCert.Verify(opts)
		ms.assert.Nil(err, "failed to verify new certificate: %v", err)

		receivedSealKey := []byte(util.MustGetenv("SEAL_KEY"))
		if reuseUUID {
			// check if we get back the same seal key
			ms.assert.Equal(sealKey, receivedSealKey)
		} else {
			// check that the seal key is different
			ms.assert.NotEqual(sealKey, receivedSealKey)
		}
		// store seal key
		sealKey = receivedSealKey
		return 0
	}

	// call preMain
	params, err := preMain(cert, privk, issuer, appFs)
	if !shouldSucceed {
		ms.assert.NotNil(err, err)
		ms.assert.Nil(params, "expected empty params, but got %v", params)
		return
	}
	ms.assert.Nil(err, "preMain failed: %v", err)
	ms.assert.NotNil(params, "got empty params: %v", params)

	ms.assert.Equal(marble.Parameters.Argv, params.Argv, "expected equal: '%v' - '%v'", marble.Parameters.Argv, params.Argv)

	pemCert := params.Env["MARBLE_CERT"]
	p, _ := pem.Decode([]byte(pemCert))
	ms.assert.NotNil(p)
	newCert, err := x509.ParseCertificate(p.Bytes)
	ms.assert.Nil(err)

	ms.assert.Equal(newCert.Issuer.CommonName, coordinatorCommonName, "expected equal: '%v' - '%v'", newCert.Issuer.CommonName, coordinatorCommonName)
	ms.assert.Equal(newCert.Subject.Organization[0], newCert.Issuer.Organization[0], "expected equal: '%v' - '%v'", newCert.Subject.Organization[0], newCert.Issuer.Organization[0])

	uuidBytes, err := afero.ReadFile(appFs, uuidFile)
	ms.assert.Nil(err, "error reading uuidFile: %v", err)
	marbleUUID, err := uuid.NewUUID()
	ms.assert.Nil(err, "error creating UUID: %v", err)
	err = marbleUUID.UnmarshalBinary(uuidBytes)
	ms.assert.Nil(err, "error unmarshaling UUID: %v", err)
	ms.assert.Equal(marbleUUID.String(), newCert.Subject.CommonName)

	// call dummyMain
	ret := dummyMain(len(os.Args), os.Args, os.Environ())
	ms.assert.Equal(0, ret, "dummyMain returned status code != 0: %v", ret)

}
