package cmd

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
)

func newManifestGet() *cobra.Command {
	var output string
	var updates bool

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

			response, err := cliManifestGet(hostName, "manifest", cert)
			if err != nil {
				return err
			}

			var updateLog []byte
			if updates {
				updateLog, err = cliManifestGet(hostName, "update", cert)
				if err != nil {
					return err
				}
			}

			if len(output) > 0 {
				f, err := os.Create(output)
				if err != nil {
					return err
				}
				if _, err := f.WriteString(string(response)); err != nil {
					return err
				}
				if updates {
					if _, err := f.WriteString(fmt.Sprintf("\n%s\n", string(updateLog))); err != nil {
						return err
					}
				}
				return nil
			}

			fmt.Printf("Manifest signature: %s\n", string(response))
			if updates {
				fmt.Println(string(updateLog))
			}
			return nil
		},
		SilenceUsage: true,
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Save singature to file instead of printing to stdout")
	cmd.Flags().BoolVarP(&updates, "update-log", "u", false, "Print a log of updates to the coordinator")
	return cmd
}

// cliManifestGet gets the manifest hash or update log from the coordinators rest api
func cliManifestGet(host, target string, cert []*pem.Block) ([]byte, error) {
	client, err := restClient(cert, nil)
	if err != nil {
		return nil, err
	}

	url := url.URL{Scheme: "https", Host: host, Path: target}
	resp, err := client.Get(url.String())
	if err != nil {
		return nil, err
	}
	if resp.Body == nil {
		return nil, errors.New("received empty response")
	}
	defer resp.Body.Close()

	jsonPath := "data"
	if target == "manifest" {
		jsonPath = "data.ManifestSignature"
	}

	switch resp.StatusCode {
	case http.StatusOK:
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		manifestData := gjson.GetBytes(respBody, jsonPath)
		return []byte(manifestData.String()), nil
	default:
		return nil, fmt.Errorf("error connecting to server: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
}
