package main

import "C"

//export invokemain
func invokemain() int {
	return premainTest()
}
