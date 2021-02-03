package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/edgelesssys/era/era"
	"github.com/spf13/cobra"
)

var eraConfig string
var insecureEra bool

const eraString = `
Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github
`

var rootCmd = &cobra.Command{
	Use:   "marblerun",
	Short: "marblerun cli short description",
	Long:  `marblerun cli long description`,
}

// Execute starts the CLI
func Execute() error {
	return rootCmd.Execute()
}

func init() {

	rootCmd.AddCommand(newManifestCmd())
	rootCmd.AddCommand(newNamespaceCmd())
	rootCmd.AddCommand(newInstallCmd())
	rootCmd.AddCommand(newRecoverCmd())
	rootCmd.AddCommand(newRootCACmd())
}

// VerifyCoordinator verifies the connection using era
func VerifyCoordinator(host string, configFilename string, insecure bool) (string, error) {
	var cert string
	var err error

	if insecure {
		// skip verification if specified
		fmt.Println("Warning: skipping quote verification")
		cert, err = era.InsecureGetCertificate(host)
		if err != nil {
			return "", err
		}
	} else if configFilename == "" {
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

		cert, err = era.GetCertificate(host, "era-config.json")
		if err != nil {
			return "", err
		}
	} else {
		cert, err = era.GetCertificate(host, configFilename)
		if err != nil {
			return "", err
		}
	}
	return cert, nil
}
