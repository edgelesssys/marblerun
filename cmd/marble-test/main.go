// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/edgelesssys/ego/marble"
	"github.com/edgelesssys/marblerun/util"
)

func main() {
	addr := util.MustGetenv("EDG_TEST_ADDR")

	if len(os.Args) > 1 && os.Args[1] == "serve" {
		runServer(addr)
		return
	}

	runClient(addr)
}

func runServer(addr string) {
	// Retrieve server TLS config from ertgolib
	tlsConfig, err := marble.GetTLSConfig(true)
	if err != nil {
		panic(err)
	}

	// Setup server
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

func runClient(addr string) error {
	// Retrieve client TLS config from ertgolib
	tlsConfig, err := marble.GetTLSConfig(false)
	if err != nil {
		panic(err)
	}

	// Setup client
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
