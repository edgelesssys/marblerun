package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
)

type coordinatorResponse struct {
	StatusMessage string `json:"StatusMessage"`
}

func newRecoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recover <IP:PORT> <recovery_key_decrypted>",
		Short: "Recovers the Marblerun coordinator from a sealed state",
		Long:  `Recovers the Marblerun coordinator from a sealed state`,
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			keyFile := args[1]
			return cliRecover(hostName, keyFile, eraConfig, insecureEra)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&eraConfig, "era-config", "", "Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github")
	cmd.Flags().BoolVarP(&insecureEra, "insecure", "i", false, "Set to skip quote verification, needed when running in simulation mode")

	return cmd
}

// cliRecover tries to unseal the coordinator by uploading the recovery key
func cliRecover(host string, keyFile string, configFilename string, insecure bool) error {
	cert, err := verifyCoordinator(host, configFilename, insecure)
	if err != nil {
		return err
	}
	fmt.Println("Successfully verified coordinator, now uploading key")

	client, err := restClient(cert)
	if err != nil {
		return err
	}

	// read in key
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return err
	}

	url := url.URL{Scheme: "https", Host: host, Path: "recover"}
	resp, err := client.Post(url.String(), "text/plain", bytes.NewReader(key))
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if len(respBody) <= 0 {
			fmt.Println("Successfully uploaded recovery key and unsealed the Marblerun coordinator")
			return nil
		}

		// if a response was sent another recovery key will be needed, print message to user
		var response coordinatorResponse
		if err := json.Unmarshal(respBody, &response); err != nil {
			return err
		}
		fmt.Printf("%s \n", response)
	default:
		return fmt.Errorf("error connecting to server: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return nil
}
