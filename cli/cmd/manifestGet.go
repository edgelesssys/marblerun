package cmd

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
	"sigs.k8s.io/yaml"
)

func newManifestGet() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "get <IP:PORT>",
		Short: "Get the manifest signature from the Marblerun coordinator",
		Long:  `Get the manifest signature from the Marblerun coordinator`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			cert, err := verifyCoordinator(hostName, eraConfig, insecureEra)
			if err != nil {
				return err
			}

			fmt.Println("Successfully verified coordinator, now requesting manifest signature")

			response, err := cliManifestGet(format, hostName, cert)
			if err != nil {
				return err
			}

			fmt.Println(string(response))
			return nil
		},
		SilenceUsage: true,
	}
	cmd.Flags().StringVarP(&format, "output", "o", "json", "Output format, either json or yaml")
	return cmd
}

// cliManifestGet gets the manifest from the coordinatros rest api
func cliManifestGet(format string, host string, cert []*pem.Block) ([]byte, error) {
	client, err := restClient(cert)
	if err != nil {
		return nil, err
	}

	url := url.URL{Scheme: "https", Host: host, Path: "manifest"}
	resp, err := client.Get(url.String())
	if err != nil {
		return nil, err
	}
	if resp.Body == nil {
		return nil, errors.New("Received empty manifest")
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		respBody, err := ioutil.ReadAll(resp.Body)
		manifestData := gjson.GetBytes(respBody, "data")
		if err != nil {
			return nil, err
		}

		if format == "yaml" {
			return yaml.JSONToYAML([]byte(manifestData.String()))
		}

		return []byte(manifestData.String()), nil
	default:
		return nil, fmt.Errorf("error connecting to server: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
}
