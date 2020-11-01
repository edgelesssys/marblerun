// Copyright (c) Edgeless Systems GmbH.
// Licensed under the MIT License.

package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello world!\nCommandline arguments:", os.Args)
	})

	fmt.Println("listening ...")
	err := http.ListenAndServe(":8080", nil)
	fmt.Println(err)
}
