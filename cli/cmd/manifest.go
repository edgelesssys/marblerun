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

func newManifestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manifest",
		Short: "Manages manifest for the MarbleRun Coordinator",
		Long: `
Manages manifests for the MarbleRun Coordinator.
Used to either set the manifest, update an already set manifest,
or return a signature of the currently set manifest to the user`,
		Example: "manifest set manifest.json example.com:4433 [--era-config=config.json] [--insecure]",
	}

	cmd.PersistentFlags().StringVar(&eraConfig, "era-config", "", "Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github")
	cmd.PersistentFlags().BoolVarP(&insecureEra, "insecure", "i", false, "Set to skip quote verification, needed when running in simulation mode")
	cmd.AddCommand(newManifestGet())
	cmd.AddCommand(newManifestLog())
	cmd.AddCommand(newManifestSet())
	cmd.AddCommand(newManifestSignature())
	cmd.AddCommand(newManifestUpdate())
	cmd.AddCommand(newManifestVerify())

	return cmd
}

// cliDataGet requests data from the Coordinators rest api.
func cliDataGet(host, target, jsonPath string, cert []*pem.Block) ([]byte, error) {
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
