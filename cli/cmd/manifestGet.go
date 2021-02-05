package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/spf13/cobra"
)

func newManifestGet() *cobra.Command {
	var manifestFilename string

	cmd := &cobra.Command{
		Use:   "get <IP:PORT>",
		Short: "Get the manifest signature from the marblerun Coordinator",
		Long:  `Get the manifest signature from the marblerun Coordinator`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			targetFile := manifestFilename
			if targetFile == "" {
				targetFile = "manifest.json"
			}
			return cliManifestGet(targetFile, hostName, eraConfig, insecureEra)
		},
		SilenceUsage: true,
	}
	cmd.Flags().StringVarP(&manifestFilename, "output", "o", "manifest.json", "Define file to write to")
	return cmd
}

// cliManifestGet gets the manifest from the coordinatros rest api
func cliManifestGet(targetFile string, host string, configFilename string, insecure bool) error {
	cert, err := verifyCoordinator(host, configFilename, insecure)
	if err != nil {
		return err
	}
	fmt.Println("Successfully verified coordinator, now requesting manifest signature")

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

	resp, err := client.Get("https://" + host + "/manifest")
	if err != nil {
		return err
	}
	if resp.Body == nil {
		return errors.New("Received empty manifest")
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if err := ioutil.WriteFile(targetFile, respBody, 0644); err != nil {
			return err
		}
		fmt.Printf("Manifest written to: %s.\n", targetFile)
	default:
		fmt.Printf("Error connecting to server: %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return nil
}
