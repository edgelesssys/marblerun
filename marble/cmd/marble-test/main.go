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
	cert := []byte(util.MustGetenv("MARBLE_CERT"))
	rootCA := []byte(util.MustGetenv("ROOT_CA"))
	privk := []byte(util.MustGetenv("MARBLE_KEY"))

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootCA) {
		log.Fatalf("cannot append rootCa to CertPool")
	}

	tlsCert, err := tls.X509KeyPair(cert, privk)
	if err != nil {
		log.Fatalf("cannot create TLS cert: %v", err)
	}

	if len(os.Args) > 1 && os.Args[1] == "serve" {
		runServer(tlsCert, roots)
		return
	}

	runClient(tlsCert, roots)
}

func runServer(tlsCert tls.Certificate, roots *x509.CertPool) {
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
	log.Println("starting server")
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func runClient(tlsCert tls.Certificate, roots *x509.CertPool) error {
	client := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{tlsCert},
	}}}
	resp, err := client.Get("https://localhost:8080/")
	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("http.Get returned: %v", resp.Status)
	}
	log.Printf("Successful connection to Server: %v", resp.Status)
	return nil
}
