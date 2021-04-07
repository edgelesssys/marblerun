package cmd

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
	"sigs.k8s.io/yaml"
)

func newManifestSet() *cobra.Command {
	var recoveryFilename string

	cmd := &cobra.Command{
		Use:   "set <manifest.json> <IP:PORT>",
		Short: "Sets the manifest for the Marblerun coordinator",
		Long:  "Sets the manifest for the Marblerun coordinator",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			manifestFile := args[0]
			hostName := args[1]

			cert, err := verifyCoordinator(hostName, eraConfig, insecureEra)
			if err != nil {
				return err
			}

			fmt.Println("Successfully verified coordinator, now uploading manifest")

			// Load manifest
			manifest, err := loadManifestFile(manifestFile)
			if err != nil {
				return err
			}
			signature := cliManifestSignature(manifest)
			fmt.Printf("Manifest signature: %s\n", signature)

			return cliManifestSet(manifest, hostName, cert, recoveryFilename)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&recoveryFilename, "recoverydata", "r", "", "File to write recovery data to, print to stdout if non specified")

	return cmd
}

// cliManifestSet sets the coordinators manifest using its rest api
func cliManifestSet(manifest []byte, host string, cert []*pem.Block, recover string) error {
	client, err := restClient(cert)
	if err != nil {
		return err
	}

	url := url.URL{Scheme: "https", Host: host, Path: "manifest"}
	resp, err := client.Post(url.String(), "application/json", bytes.NewReader(manifest))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		fmt.Println("Manifest successfully set")

		if len(respBody) <= 0 {
			return nil
		}

		response := gjson.GetBytes(respBody, "data")

		// Skip outputting secrets if we do not get any recovery secrets back
		if len(response.String()) == 0 {
			return nil
		}

		// recovery secret was sent, print or save to file
		if recover == "" {
			fmt.Println(response.String())
		} else {
			if err := ioutil.WriteFile(recover, []byte(response.String()), 0644); err != nil {
				return err
			}
			fmt.Printf("Recovery data saved to: %s.\n", recover)
		}
	case http.StatusBadRequest:
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		response := gjson.GetBytes(respBody, "message")
		return fmt.Errorf(response.String())
	default:
		return fmt.Errorf("error connecting to server: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return nil
}

// loadManifestFile loads a manifest in either json or yaml format and returns the data as json
func loadManifestFile(filename string) ([]byte, error) {
	manifestData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// if Valid is true the file was in JSON format and we can just return the data
	if json.Valid(manifestData) {
		return manifestData, err
	}

	// otherwise we try to convert from YAML to json
	return yaml.YAMLToJSON(manifestData)
}
