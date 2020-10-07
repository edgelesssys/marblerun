package util

import (
	"fmt"
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
