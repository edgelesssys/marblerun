package main

import "C"

//export invokemain
func invokemain(coordinatorAddr, marbleType, marbleDNSNames *C.char) int {
	return marbleTest(C.GoString(coordinatorAddr), C.GoString(marbleType), C.GoString(marbleDNSNames))
}
