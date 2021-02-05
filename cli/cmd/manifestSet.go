package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

func newManifestSet() *cobra.Command {
	var recoveryFilename string

	cmd := &cobra.Command{
		Use:   "set <manifest.json> <IP:PORT>",
		Short: "Sets the manifest for the marblerun Coordinator",
		Long:  "Sets the manifest for the marblerun Coordinator",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			manifestFile := args[0]
			hostName := args[1]
			return cliManifestSet(manifestFile, hostName, eraConfig, insecureEra, recoveryFilename)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&recoveryFilename, "recoverydata", "r", "", "File to write recovery data to, print to stdout if non specified")

	return cmd
}

// cliManifestSet sets the coordinators manifest using its rest api
func cliManifestSet(manifestName string, host string, configFilename string, insecure bool, recover string) error {
	cert, err := verifyCoordinator(host, configFilename, insecure)
	if err != nil {
		return err
	}
	fmt.Println("Successfully verified coordinator, now uploading manifest")

	// Set rootCA for connection to coordinator
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return err
	}
	if certPool == nil {
		certPool = x509.NewCertPool()
	}
	if ok := certPool.AppendCertsFromPEM([]byte(cert)); !ok {
		return errors.New("Failed to parse certificate")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}

	f, err := os.Open(manifestName)
	if err != nil {
		return err
	}
	defer f.Close()

	// Load manifest
	manifest, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	resp, err := client.Post("https://"+host+"/manifest", "application/json", bytes.NewBuffer(manifest))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		fmt.Printf("Manifest successfully set\n")

		// Check if recovery secret was sent back
		if string(respBody) != "" {
			if recover == "" {
				fmt.Println(string(respBody))
			} else {
				if err := ioutil.WriteFile(recover, respBody, 0644); err != nil {
					return err
				}
				fmt.Printf("Manifest successfully set, recovery data saved to: %s.\n", recover)
			}
		}
	case 400:
		fmt.Printf("Unable to set manifest: Server is not in expected state.\nDid you mean to update the manifest?\n")
	default:
		fmt.Printf("Error connecting to server: %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return nil
}
