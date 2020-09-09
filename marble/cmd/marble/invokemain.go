package main

import "C"

//export invokemain
func invokemain(coordinatorAddr, marbleType *C.char) int {
	return marbleTest(C.GoString(coordinatorAddr), C.GoString(marbleType))
}
