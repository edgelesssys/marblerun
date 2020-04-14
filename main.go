package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {

	http.HandleFunc("/bar", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			panic(err)
		}
		p0 := r.Form.Get("param0")
		fmt.Fprintf(w, "Hello, %s", p0)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
