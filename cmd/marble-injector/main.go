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
	var sgxResource string
	flag.StringVar(&addr, "coordAddr", "coordinator-mesh-api.marblerun:2001", "Address of the MarbleRun coordinator")
	flag.StringVar(&certFile, "tlsCertFile", "/etc/webhook/certs/cert.pem", "File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&keyFile, "tlsKeyFile", "/etc/webhook/certs/key.pem", "File containing the x509 private key to --tlsCertFile.")
	flag.StringVar(&clusterDomain, "clusterDomain", "cluster.local", "Domain name of the kubernetes cluster")
	flag.StringVar(&sgxResource, "sgxResource", "sgx.intel.com/epc", "Defines the resource/toleration to inject, this needs to be exposed on a node through a device plugin")

	flag.Parse()

	mux := http.NewServeMux()
	w := &injector.Mutator{
		CoordAddr:   addr,
		DomainName:  clusterDomain,
		SGXResource: sgxResource,
	}

	mux.HandleFunc("/mutate", w.HandleMutate)

	s := &http.Server{
		// Addresse forwarding to 443 should be handled by the marble-injector service object
		Addr:    ":8443",
		Handler: mux,
	}

	log.Println("Starting Server")
	log.Fatal(s.ListenAndServeTLS(certFile, keyFile))
}
