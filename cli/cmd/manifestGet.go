package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
)

func newManifestGet() *cobra.Command {
	var manifestFilename string

	cmd := &cobra.Command{
		Use:   "get <IP:PORT>",
		Short: "Get the manifest signature from the Marblerun coordinator",
		Long:  `Get the manifest signature from the Marblerun coordinator`,
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

	client, err := restClient(cert)
	if err != nil {
		return err
	}

	url := url.URL{Scheme: "https", Host: host, Path: "manifest"}
	resp, err := client.Get(url.String())
	if err != nil {
		return err
	}
	if resp.Body == nil {
		return errors.New("Received empty manifest")
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if err := ioutil.WriteFile(targetFile, respBody, 0644); err != nil {
			return err
		}
		fmt.Printf("Manifest written to: %s.\n", targetFile)
	default:
		return fmt.Errorf("error connecting to server: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return nil
}
