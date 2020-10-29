package util

import (
	"fmt"
	"net"
	"os"
)

// MustGetenv returns the environment variable `name` if it exists or panics otherwise
func MustGetenv(name string) string {
	value := os.Getenv(name)
	if len(value) == 0 {
		panic(fmt.Errorf("environment variable not set: %v", name))
	}
	return value
}

// MustGetLocalListenerAndAddr returns a TCP listener on a system-chosen port on localhost and its address.
func MustGetLocalListenerAndAddr() (net.Listener, string) {
	const localhost = "localhost:"

	listener, err := net.Listen("tcp", localhost)
	if err != nil {
		panic(err)
	}

	addr := listener.Addr().String()

	// addr contains IP address, we want hostname
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	return listener, localhost + port
}
