package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/edgelesssys/coordinator/util"
)

func main() {
	isServer := len(os.Args) > 0 && os.Args[0] == "serve"
	tlsCertPem, tlsCertRaw, err := parsePemFromEnv("MARBLE_CERT")
	if err != nil {
		log.Fatalf("failed to get TLS Certificate: %v", err)
	}
	_, rootCARaw, err := parsePemFromEnv("ROOT_CA")
	if err != nil {
		log.Fatalf("failed to get root CA: %v", err)
	}
	_, privkRaw, err := parsePemFromEnv("MARBLE_KEY")
	if err != nil {
		log.Fatalf("failed to get private key: %v", err)
	}
	_, _, err = parsePemFromEnv("SEAL_KEY")
	if err != nil {
		log.Fatalf("failed to get seal key: %v", err)
	}

	// Verify certificate chain
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootCARaw) {
		log.Fatal("authentication error")
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		CurrentTime:   time.Now(),
		DNSName:       "localhost",
		Intermediates: x509.NewCertPool(),
	}
	tlsCert, err := x509.ParseCertificate(tlsCertPem.Bytes)
	if err != nil {
		log.Fatal("authentication error")
	}
	_, err = tlsCert.Verify(opts)
	if err != nil {
		log.Fatalf("failed to verify certificate chain: %v", err)
	}

	// Run actual server-client application
	if isServer {
		runServer(tlsCertRaw, privkRaw, rootCARaw)
		return
	}
	err = runClient(tlsCertRaw, privkRaw, rootCARaw)
	if err != nil {
		log.Fatalf("failed to make connection to server: %v", err)
	}
}

func parsePemFromEnv(certName string) (*pem.Block, []byte, error) {
	certRaw := util.MustGetenv(certName)
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
