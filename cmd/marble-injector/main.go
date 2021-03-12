package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/edgelesssys/marblerun/injector"
)

func main() {
	var certFile string
	var keyFile string
	var addr string
	var clusterDomain string
	flag.StringVar(&addr, "coordAddr", "coordinator-mesh-api.marblerun:25554", "Address of the Marblerun coordinator")
	flag.StringVar(&certFile, "tlsCertFile", "/etc/webhook/certs/cert.pem", "File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&keyFile, "tlsKeyFile", "/etc/webhook/certs/key.pem", "File containing the x509 private key to --tlsCertFile.")
	flag.StringVar(&clusterDomain, "clusterDomain", "cluster.local", "Domain name of the kubernetes cluster")

	flag.Parse()

	mux := http.NewServeMux()
	w := &injector.Mutator{CoordAddr: addr, DomainName: clusterDomain}

	mux.HandleFunc("/mutate", w.HandleMutate)
	mux.HandleFunc("/mutate-no-sgx", w.HandleMutateNoSgx)

	s := &http.Server{
		// Addresse forwarding to 443 should be handled by the marble-injector service object
		Addr:    ":8443",
		Handler: mux,
	}

	log.Println("Starting Server")
	log.Fatal(s.ListenAndServeTLS(certFile, keyFile))
}
