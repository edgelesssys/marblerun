// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/edgelesssys/marblerun/util"
)

func main() {
	cert := []byte(util.MustGetenv("MARBLE_CERT"))
	rootCA := []byte(util.MustGetenv("ROOT_CA"))
	privk := []byte(util.MustGetenv("MARBLE_KEY"))
	addr := util.MustGetenv("EDG_TEST_ADDR")

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootCA) {
		log.Fatalf("cannot append rootCa to CertPool")
	}

	tlsCert, err := tls.X509KeyPair(cert, privk)
	if err != nil {
		log.Fatalf("cannot create TLS cert: %v", err)
	}

	if len(os.Args) > 1 && os.Args[1] == "serve" {
		runServer(addr, tlsCert, roots)
		return
	}

	runClient(addr, tlsCert, roots)
}

func runServer(addr string, tlsCert tls.Certificate, roots *x509.CertPool) {
	srv := &http.Server{
		Addr: addr,
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

func runClient(addr string, tlsCert tls.Certificate, roots *x509.CertPool) error {
	client := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{tlsCert},
	}}}
	url := url.URL{Scheme: "https", Host: addr}
	resp, err := client.Get(url.String())
	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("http.Get returned: %v", resp.Status)
	}
	log.Printf("Successful connection to Server: %v", resp.Status)
	return nil
}
