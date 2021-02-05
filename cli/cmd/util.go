package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/edgelesssys/era/era"
)

var eraConfig string
var insecureEra bool

// verify the connection to the marblerun coordinator
func verifyCoordinator(host string, configFilename string, insecure bool) (string, error) {
	// skip verification if specified
	if insecure {
		fmt.Println("Warning: skipping quote verification")
		return era.InsecureGetCertificate(host)
	}

	// get certificate using provided config
	if configFilename != "" {
		return era.GetCertificate(host, configFilename)
	}

	// get latest config from github if none specified
	fmt.Println("No era config file specified, getting latest config from github.com/edgelesssys/marblerun/releases/latest/download/coordinator-era.json")
	resp, err := http.Get("https://github.com/edgelesssys/marblerun/releases/latest/download/coordinator-era.json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	out, err := os.Create("era-config.json")
	if err != nil {
		return "", err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return "", err
	}
	fmt.Println("Got latest config")

	return era.GetCertificate(host, "era-config.json")
}
