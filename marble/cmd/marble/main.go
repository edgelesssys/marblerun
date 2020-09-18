package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/marble/marble"
)

const (
	Success             int = 0
	InternalError       int = 2
	AuthenticationError int = 4
	UsageError          int = 8
)

func main() {}

func premainTarget(argc int, argv []string, env []string) int {
	isServer := argc > 0 && argv[0] == "serve"
	tlsCertPem, tlsCertRaw, err := parsePemFromEnv(env, "MARBLE_CERT")
	if err != nil {
		log.Fatalf("failed to get TLS Certificate: %v", err)
	}
	_, rootCARaw, err := parsePemFromEnv(env, "ROOT_CA")
	if err != nil {
		log.Fatalf("failed to get root CA: %v", err)
	}
	_, privkRaw, err := parsePemFromEnv(env, "MARBLE_KEY")
	if err != nil {
		log.Fatalf("failed to get private key: %v", err)
	}
	_, _, err = parsePemFromEnv(env, "SEAL_KEY")
	if err != nil {
		log.Fatalf("failed to get seal key: %v", err)
	}

	// Verify certificate chain
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootCARaw) {
		return AuthenticationError
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		CurrentTime:   time.Now(),
		DNSName:       "localhost",
		Intermediates: x509.NewCertPool(),
	}
	tlsCert, err := x509.ParseCertificate(tlsCertPem.Bytes)
	if err != nil {
		return AuthenticationError
	}
	_, err = tlsCert.Verify(opts)
	if err != nil {
		log.Fatalf("failed to verify certificate chain: %v", err)
		return UsageError
	}

	// Run actual server-client application
	if isServer {
		runServer(tlsCertRaw, privkRaw, rootCARaw)
		return Success
	}
	err = runClient(tlsCertRaw, privkRaw, rootCARaw)
	if err != nil {
		log.Fatalf("failed to make connection to server: %v", err)
		return UsageError
	}
	return Success
}

func parsePemFromEnv(env []string, certName string) (*pem.Block, []byte, error) {
	certRaw := os.Getenv(certName)
	if len(certRaw) == 0 {
		return nil, nil, fmt.Errorf("could not find certificate in env")
	}
	certPem, _ := pem.Decode([]byte(certRaw))
	if certPem == nil {
		return nil, nil, fmt.Errorf("could not decode certificate in PEM format")
	}

	return certPem, []byte(certRaw), nil
}

func runServer(certRaw []byte, keyRaw []byte, rootCARaw []byte) {
	// generate server with TLSConfig
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootCARaw) {
		log.Fatalf("cannot append rootCa to CertPool")
		return
	}
	tlsCert, err := tls.X509KeyPair(certRaw, keyRaw)
	if err != nil {
		log.Fatalf("cannot create TLS cert: %v", err)
		return
	}
	srv := &http.Server{
		Addr: "localhost:8080",
		TLSConfig: &tls.Config{
			ClientCAs:    roots,
			Certificates: []tls.Certificate{tlsCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
		},
	}

	// handle '/' route
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Welcome to this Marbelous world!")
	})

	// run sever
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func runClient(certRaw []byte, keyRaw []byte, rootCARaw []byte) error {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(rootCARaw)
	tlsCert, err := tls.X509KeyPair(certRaw, keyRaw)
	client := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{tlsCert},
	}}}
	resp, err := client.Get("https://localhost:8080/")
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http.Get returned: %v", resp.Status)
	}
	log.Printf("Successful connection to Server: %v", resp.Status)
	return nil
}

func marbleTest(config string) int {
	cfg := struct {
		CoordinatorAddr string
		MarbleType      string
		DNSNames        string
		DataPath        string
	}{}
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		panic(err)
	}
	// mount data dir
	mountData(cfg.DataPath) // mounts DataPath to /marble/data
	// set env vars
	if err := os.Setenv(marble.EdgCoordinatorAddr, cfg.CoordinatorAddr); err != nil {
		log.Fatalf("failed to set env variable: %v", err)
		return InternalError
	}
	if err := os.Setenv(marble.EdgMarbleType, cfg.MarbleType); err != nil {
		log.Fatalf("failed to set env variable: %v", err)
		return InternalError
	}

	if err := os.Setenv(marble.EdgMarbleDNSNames, cfg.DNSNames); err != nil {
		log.Fatalf("failed to set env variable: %v", err)
		return InternalError
	}
	uuidFile := filepath.Join("marble", "data", "uuid")
	if err := os.Setenv(marble.EdgMarbleUUIDFile, uuidFile); err != nil {
		log.Fatalf("failed to set env variable: %v", err)
		return InternalError
	}

	// call PreMain
	issuer := quote.NewERTIssuer()
	a, err := marble.NewAuthenticator(issuer)
	if err != nil {
		return InternalError
	}
	_, err = marble.PreMain(a, premainTarget)
	if err != nil {
		fmt.Println(err)
		return AuthenticationError
	}
	log.Println("Successfully authenticated with Coordinator!")
	return Success
}
