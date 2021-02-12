package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/edgelesssys/marblerun/webhook/mutate"
)

func main() {
	var certFile string
	var keyFile string
	flag.StringVar(&mutate.CoordAddr, "coordAddr", "coordinator-mesh-api.marblerun:25554", "Address of the Marblerun coordinator")
	flag.StringVar(&certFile, "tlsCertFile", "/etc/webhook/certs/cert.pem", "File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&keyFile, "tlsKeyFile", "/etc/webhook/certs/key.pem", "File containing the x509 private key to --tlsCertFile.")
	mux := http.NewServeMux()

	mux.HandleFunc("/mutate", mutate.HandleMutate)
	mux.HandleFunc("/mutate-no-sgx", mutate.HandleMutateNoSgx)

	s := &http.Server{
		// Addresse forwarding to 443 should be handled by the webhook service object
		Addr:    ":8443",
		Handler: mux,
	}

	log.Println("Starting Server")
	log.Fatal(s.ListenAndServeTLS(certFile, keyFile))
}
