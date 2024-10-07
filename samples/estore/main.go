// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"os"

	"github.com/edgelesssys/estore"
	"github.com/edgelesssys/marblerun/api"
)

func main() {
	// Get encryption key from secure environment
	encryptionKey, err := base64.StdEncoding.DecodeString(os.Getenv("ENCRYPTION_KEY"))
	if err != nil {
		log.Fatal(err)
	}

	// Create an encrypted store and enable rollback protection by using a monotonic counter provided by the Coordinator
	opts := &estore.Options{
		EncryptionKey:       encryptionKey,
		SetMonotonicCounter: setMonotonicCounter,
	}
	db, err := estore.Open("db", opts)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	tx := db.NewTransaction(true)
	defer tx.Close()

	// Set a key-value pair
	key := fmt.Appendf(nil, "hello %v", rand.Int())
	value := fmt.Appendf(nil, "world %v", rand.Int())
	if err := tx.Set(key, value, nil); err != nil {
		log.Fatal(err)
	}

	// Print all key-value pairs added so far
	iter := tx.NewIter(&estore.IterOptions{LowerBound: []byte("hello"), UpperBound: []byte("hello~")})
	for iter.First(); iter.Valid(); iter.Next() {
		fmt.Printf("%s = %s\n", iter.Key(), iter.Value())
	}
	iter.Close()

	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}
}

func setMonotonicCounter(value uint64) (uint64, error) {
	endpoint := os.Getenv("EDG_COORDINATOR_CLIENT_ADDR")
	return api.SetMonotonicCounter(context.Background(), endpoint, "my-estore-counter", value)
}
