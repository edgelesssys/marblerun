package main

import "C"

import (
	"os"

	"github.com/edgelesssys/coordinator/marble/premain"
)

var cargs []*C.char

//export invokemain
func invokemain() { main() }

//export ert_meshentry_premain
func ert_meshentry_premain(argc *C.int, argv ***C.char) {
	if err := premain.PreMain(); err != nil {
		panic(err)
	}

	cargs = make([]*C.char, len(os.Args)+1)
	for i, a := range os.Args {
		cargs[i] = C.CString(a)
	}

	*argc = C.int(len(os.Args))
	*argv = &cargs[0]
}
