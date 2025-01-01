/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/edgelesssys/ego/marble"
	"github.com/edgelesssys/marblerun/api"
	"github.com/edgelesssys/marblerun/util"
)

func main() {
	addr := util.MustGetenv("EDG_TEST_ADDR")

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
			runServer(addr, true)
			return
		case "serve-no-client-auth":
			runServer(addr, false)
			return
		case "monotonic-counter":
			if err := testMonotonicCounter(); err != nil {
				log.Fatal(err)
			}
			return
		}
	}

	if err := runClient(addr); err != nil {
		log.Fatal(err)
	}
}

func runServer(addr string, verifyClientCerts bool) {
	// Retrieve server TLS config from ertgolib
	tlsConfig, err := marble.GetTLSConfig(verifyClientCerts)
	if err != nil {
		panic(err)
	}

	// Setup server
	srv := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
	}

	// handle '/' route
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
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
		return err
	}

	// Setup client
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	url := url.URL{Scheme: "https", Host: addr}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url.String(), http.NoBody)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http.Get returned: %s", resp.Status)
	}
	log.Printf("Successful connection to Server: %v", resp.Status)
	return nil
}

func testMonotonicCounter() error {
	const counterName = "foo"
	endpoint := os.Getenv("EDG_COORDINATOR_CLIENT_ADDR")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	value, err := api.SetMonotonicCounter(ctx, endpoint, counterName, 2)
	if err != nil {
		return fmt.Errorf("first call to SetMonotonicCounter: %w", err)
	}
	if value != 0 {
		return fmt.Errorf("expected initial value 0, got %v", value)
	}

	value, err = api.SetMonotonicCounter(ctx, endpoint, counterName, 3)
	if err != nil {
		return fmt.Errorf("second call to SetMonotonicCounter: %w", err)
	}
	if value != 2 {
		return fmt.Errorf("expected previous value 2, got %v", value)
	}

	return nil
}
