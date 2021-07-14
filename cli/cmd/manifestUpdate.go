package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
)

func newManifestUpdate() *cobra.Command {
	var clientAdminCert string
	var clientAdminKey string

	cmd := &cobra.Command{
		Use:   "update <manifest.json> <IP:PORT>",
		Short: "Updates the Marblerun Coordinator with the specified manifest",
		Long: `
Updates the Marblerun Coordinator with the specified manifest.
An admin certificate specified in the original manifest is needed to verify the authenticity of the update manifest.
`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			manifestFile := args[0]
			hostName := args[1]

			caCert, err := verifyCoordinator(hostName, eraConfig, insecureEra)
			if err != nil {
				return err
			}

			// Load client certificate and key
			clCert, err := tls.LoadX509KeyPair(clientAdminCert, clientAdminKey)
			if err != nil {
				return err
			}

			// Load manifest
			manifest, err := loadManifestFile(manifestFile)
			if err != nil {
				return err
			}

			fmt.Println("Successfully verified Coordinator, now uploading manifest")

			return cliManifestUpdate(manifest, hostName, clCert, caCert)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&clientAdminCert, "cert", "c", "", "PEM encoded admin certificate file (required)")
	cmd.MarkFlagRequired("cert")
	cmd.Flags().StringVarP(&clientAdminKey, "key", "k", "", "PEM encoded admin key file (required)")
	cmd.MarkFlagRequired("key")

	return cmd
}

// cliManifestUpdate updates the Coordinators manifest using its rest api
func cliManifestUpdate(manifest []byte, host string, clCert tls.Certificate, caCert []*pem.Block) error {
	client, err := restClient(caCert, &clCert)
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
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		response := gjson.GetBytes(respBody, "message")
		return fmt.Errorf("unable to update manifest: %s", response.String())
	case http.StatusUnauthorized:
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		response := gjson.GetBytes(respBody, "message")
		return fmt.Errorf("unable to authorize user: %s", response.String())
	default:
		return fmt.Errorf("error connecting to server: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return nil
}
