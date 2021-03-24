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
)

func newManifestGet() *cobra.Command {
	var output string

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

			response, err := cliManifestGet(hostName, cert)
			if err != nil {
				return err
			}

			if len(output) > 0 {
				return ioutil.WriteFile(output, response, 0644)
			}

			fmt.Printf("Manifest signature: %s\n", string(response))
			return nil
		},
		SilenceUsage: true,
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Save singature to file instead of printing to stdout")
	return cmd
}

// cliManifestGet gets the manifest from the coordinatros rest api
func cliManifestGet(host string, cert []*pem.Block) ([]byte, error) {
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
		if err != nil {
			return nil, err
		}
		manifestData := gjson.GetBytes(respBody, "data.ManifestSignature")
		return []byte(manifestData.String()), nil
	default:
		return nil, fmt.Errorf("error connecting to server: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
}
