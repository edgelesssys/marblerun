package coordinator

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"testing"
	"time"
)

var exe = flag.String("e", "", "Coordinator executable")
var addrAPI, addrDB string

func TestMain(m *testing.M) {
	flag.Parse()
	if *exe == "" {
		log.Fatalln("You must provide the path of the coordinator executable using th -e flag.")
	}
	if _, err := os.Stat(*exe); err != nil {
		log.Fatalln(err)
	}

	// get unused ports
	var listenerAPI, listenerDB net.Listener
	listenerAPI, addrAPI = getListenerAndAddr()
	listenerDB, addrDB = getListenerAndAddr()
	listenerAPI.Close()
	listenerDB.Close()

	fmt.Println(addrAPI)
	fmt.Println(addrDB)
	os.Exit(m.Run())
}

func getListenerAndAddr() (net.Listener, string) {
	const localhost = "localhost:"

	listener, err := net.Listen("tcp", localhost)
	if err != nil {
		panic(err)
	}

	addr := listener.Addr().String()

	// addr contains IP address, we want hostname
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	return listener, localhost + port
}

// sanity test of the integration test environment
func TestTest(t *testing.T) {
	//assert := assert.New(t)
	cfgFilename := createConfig()
	defer cleanupConfig(cfgFilename)
	fmt.Println(startCoordinator(cfgFilename))
	//assert.Nil(startCoordinator(cfgFilename).Kill())
}

/*
func TestReaderWriter(t *testing.T) {
	assert := assert.New(t)

	caCert, caKey := createCertificate("Owner CA", "", "")
	readerCert, readerKey := createCertificate("Reader", caCert, caKey)
	writerCert, writerKey := createCertificate("Writer", caCert, caKey)

	manifest := createManifest(caCert, []string{
		"CREATE USER reader REQUIRE ISSUER '/CN=Owner CA' SUBJECT '/CN=Reader'",
		"CREATE USER writer REQUIRE ISSUER '/CN=Owner CA' SUBJECT '/CN=Writer'",
		"CREATE TABLE test.data (i INT)",
		"GRANT SELECT ON test.data TO reader",
		"GRANT INSERT ON test.data TO writer",
	})

	cfgFilename := createConfig()
	defer cleanupConfig(cfgFilename)
	process := startEDB(cfgFilename)
	assert.NotNil(process)
	defer process.Kill()

	// Owner
	{
		serverCert, err := edbra.InsecureGetCertificate(addrAPI)
		assert.Nil(err)
		assert.Nil(postManifest(serverCert, manifest))
	}

	// Writer
	{
		serverCert, err := edbra.InsecureGetCertificate(addrAPI)
		assert.Nil(err)
		sig, err := edbra.GetManifestSignature(addrAPI, serverCert)
		assert.Nil(err)
		assert.Equal(calculateManifestSignature(manifest), sig)

		db := sqlOpen("writer", writerCert, writerKey, serverCert)
		_, err = db.Exec("INSERT INTO test.data VALUES (2), (6)")
		db.Close()
		assert.Nil(err)
	}

	// Reader
	{
		serverCert, err := edbra.InsecureGetCertificate(addrAPI)
		assert.Nil(err)
		sig, err := edbra.GetManifestSignature(addrAPI, serverCert)
		assert.Nil(err)
		assert.Equal(calculateManifestSignature(manifest), sig)

		var avg float64
		db := sqlOpen("reader", readerCert, readerKey, serverCert)
		assert.Nil(db.QueryRow("SELECT AVG(i) FROM test.data").Scan(&avg))
		_, err = db.Exec("INSERT INTO test.data VALUES (3)")
		db.Close()
		assert.NotNil(err)
		assert.Equal(4., avg)
	}
}
*/

type config struct {
	DataPath        string
	DatabaseAddress string
	APIAddress      string
}

func createConfig() string {
	cfg := config{DatabaseAddress: addrDB, APIAddress: addrAPI}
	var err error
	cfg.DataPath, err = ioutil.TempDir("", "")
	if err != nil {
		panic(err)
	}

	jsonCfg, err := json.Marshal(cfg)
	if err != nil {
		os.RemoveAll(cfg.DataPath)
		panic(err)
	}

	file, err := ioutil.TempFile("", "")
	if err != nil {
		os.RemoveAll(cfg.DataPath)
		panic(err)
	}

	name := file.Name()

	_, err = file.Write(jsonCfg)
	file.Close()
	if err != nil {
		os.Remove(name)
		os.RemoveAll(cfg.DataPath)
		panic(err)
	}

	return name
}

func cleanupConfig(filename string) {
	jsonCfg, err := ioutil.ReadFile(filename)
	os.Remove(filename)
	if err != nil {
		panic(err)
	}
	var cfg config
	if err := json.Unmarshal(jsonCfg, &cfg); err != nil {
		panic(err)
	}
	if err := os.RemoveAll(cfg.DataPath); err != nil {
		panic(err)
	}
}

func startCoordinator(configFilename string) *os.Process {
	cmd := exec.Command(*exe, "-c", configFilename)
	if err := cmd.Start(); err != nil {
		panic(err)
	}
	return nil
	/*
		// Wait on the command so that cmd.ProcessState will be updated if the process dies.
		go cmd.Wait()

		client := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		url := url.URL{Scheme: "https", Host: addrAPI, Path: "signature"}

		log.Println("Coordinator starting ...")
		for {
			time.Sleep(10 * time.Millisecond)
			if cmd.ProcessState != nil { // process died?
				return nil
			}
			resp, err := client.Head(url.String())
			if err == nil {
				log.Println("Coordinator started")
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					panic(resp.Status)
				}
				return cmd.Process
			}
		}
	*/
}

func createCertificate(commonName, signerCert, signerKey string) (cert, key string) {
	template := &x509.Certificate{
		SerialNumber: &big.Int{},
		Subject:      pkix.Name{CommonName: commonName},
		NotAfter:     time.Now().Add(time.Hour),
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	var certBytes []byte

	if signerCert == "" {
		template.BasicConstraintsValid = true
		template.IsCA = true
		certBytes, _ = x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	} else {
		signer, _ := tls.X509KeyPair([]byte(signerCert), []byte(signerKey))
		parsedSignerCert, _ := x509.ParseCertificate(signer.Certificate[0])
		certBytes, _ = x509.CreateCertificate(rand.Reader, template, parsedSignerCert, &priv.PublicKey, signer.PrivateKey)
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	return string(pemCert), string(pemKey)
}

func createManifest(ca string, sql []string) []byte {
	manifest := struct {
		SQL []string
		CA  string
	}{sql, ca}
	jsonManifest, err := json.Marshal(manifest)
	if err != nil {
		panic(err)
	}
	return jsonManifest
}

func calculateManifestSignature(manifest []byte) string {
	hash := sha256.Sum256(manifest)
	return hex.EncodeToString(hash[:])
}

func postManifest(serverCert string, manifest []byte) error {
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM([]byte(serverCert)); !ok {
		panic("AppendCertsFromPEM failed")
	}

	client := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	url := url.URL{Scheme: "https", Host: addrAPI, Path: "manifest"}

	resp, err := client.Post(url.String(), "", bytes.NewReader(manifest))
	if err != nil {
		panic(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}
