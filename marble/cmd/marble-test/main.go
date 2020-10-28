package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/edgelesssys/coordinator/util"
)

func main() {
	isServer := len(os.Args) > 0 && os.Args[0] == "serve"
	cert := []byte(util.MustGetenv("MARBLE_CERT"))
	rootCA := []byte(util.MustGetenv("ROOT_CA"))
	privk := []byte(util.MustGetenv("MARBLE_KEY"))

	// Run actual server-client application
	if isServer {
		runServer(cert, privk, rootCA)
		return
	}
	err := runClient(cert, privk, rootCA)
	if err != nil {
		log.Fatalf("failed to make connection to server: %v", err)
	}
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
