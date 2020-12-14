// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/edgelesssys/ertgolib/marble"
	"github.com/edgelesssys/marblerun/util"
)

func main() {
	addr := util.MustGetenv("EDG_TEST_ADDR")

	serverTLSConfig, err := marble.GetServerTLSConfig()
	if err != nil {
		panic(err)
	}

	clientTLSConfig, err := marble.GetClientTLSConfig()
	if err != nil {
		panic(err)
	}

	if len(os.Args) > 1 && os.Args[1] == "serve" {
		runServer(addr, serverTLSConfig)
		return
	}

	runClient(addr, clientTLSConfig)
}

func runServer(addr string, tlsConfig *tls.Config) {
	srv := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
	}

	// handle '/' route
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Welcome to this Marbelous world!")
	})

	// run sever
	log.Println("starting server")
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func runClient(addr string, tlsConfig *tls.Config) error {
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
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
