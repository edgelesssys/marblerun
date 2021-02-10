package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
)

func newManifestUpdate() *cobra.Command {
	var clientAdminCert string
	var clientAdminKey string

	cmd := &cobra.Command{
		Use:   "update <manifest.json> <IP:PORT>",
		Short: "Updates the Marblerun coordinator with the specified manifest",
		Long: `
Updates the Marblerun coordinator with the specified manifest.
An admin certificate specified in the original manifest is needed to verify the authenticity of the update manifest.
`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			manifestFile := args[0]
			hostName := args[1]
			return cliManifestUpdate(manifestFile, hostName, clientAdminCert, clientAdminKey, eraConfig, insecureEra)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&clientAdminCert, "cert", "c", "", "PEM encoded admin certificate file (required)")
	cmd.MarkFlagRequired("cert")
	cmd.Flags().StringVarP(&clientAdminKey, "key", "k", "", "PEM encoded admin key file (required)")
	cmd.MarkFlagRequired("key")

	return cmd
}

// cliManifestUpdate updates the coordinators manifest using its rest api
func cliManifestUpdate(manifestName string, host string, clCertFile string, clKeyFile string, configFilename string, insecure bool) error {
	caCert, err := verifyCoordinator(host, configFilename, insecure)
	if err != nil {
		return err
	}
	fmt.Println("Successfully verified coordinator, now uploading manifest")

	// Set rootCA for connection to coordinator
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM([]byte(caCert[0].Bytes)); !ok {
		return errors.New("Failed to parse certificate")
	}
	// Add intermediate cert if applicable
	if len(caCert) > 1 {
		if ok := certPool.AppendCertsFromPEM([]byte(caCert[1].Bytes)); !ok {
			return errors.New("Failed to parse certificate")
		}
	}

	// Load client certificate and key
	clCert, err := tls.LoadX509KeyPair(clCertFile, clKeyFile)
	if err != nil {
		return err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      certPool,
				Certificates: []tls.Certificate{clCert},
			},
		},
	}

	// Load manifest
	manifest, err := ioutil.ReadFile(manifestName)
	if err != nil {
		return err
	}

	url := url.URL{Scheme: "https", Host: host, Path: "update"}
	resp, err := client.Post(url.String(), "application/json", bytes.NewReader(manifest))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		fmt.Println("Manifest successfully updated")
	case http.StatusBadRequest:
		return fmt.Errorf("unable to update manifest: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	case http.StatusUnauthorized:
		return fmt.Errorf("unable to authorize user: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	default:
		return fmt.Errorf("error connecting to server: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return nil
}
