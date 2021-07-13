package cmd

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
)

func newRecoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recover <recovery_key_decrypted> <IP:PORT>",
		Short: "Recovers the Marblerun Coordinator from a sealed state",
		Long:  `Recovers the Marblerun Coordinator from a sealed state`,
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyFile := args[0]
			hostName := args[1]

			cert, err := verifyCoordinator(hostName, eraConfig, insecureEra)
			if err != nil {
				return err
			}

			// read in key
			recoveryKey, err := ioutil.ReadFile(keyFile)
			if err != nil {
				return err
			}

			fmt.Println("Successfully verified Coordinator, now uploading key")

			return cliRecover(hostName, recoveryKey, cert)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&eraConfig, "era-config", "", "Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github")
	cmd.Flags().BoolVarP(&insecureEra, "insecure", "i", false, "Set to skip quote verification, needed when running in simulation mode")

	return cmd
}

// cliRecover tries to unseal the Coordinator by uploading the recovery key
func cliRecover(host string, key []byte, cert []*pem.Block) error {
	client, err := restClient(cert, nil)
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
		jsonResponse := gjson.GetBytes(respBody, "data.StatusMessage")
		fmt.Printf("%s \n", jsonResponse.String())
	default:
		return fmt.Errorf("error connecting to server: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return nil
}
