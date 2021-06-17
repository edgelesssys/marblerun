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

func newSecretSet() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <secret_name> <IP:PORT>",
		Short: "Set a secret for the Marblerun coordinator",
		Long: `
Set a secret for the Marblerun coordinator.
A user has to authenticate themselves using a certificate and private key,
and has to be permitted to write the requested secrets.
`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			secretFile := args[0]
			hostName := args[1]

			caCert, err := verifyCoordinator(hostName, eraConfig, insecureEra)
			if err != nil {
				return err
			}

			// Load client certificate and key
			clCert, err := tls.LoadX509KeyPair(userCertFile, userKeyFile)
			if err != nil {
				return err
			}

			newSecrets, err := ioutil.ReadFile(secretFile)
			if err != nil {
				return err
			}

			return cliSecretSet(hostName, newSecrets, clCert, caCert)
		},
		SilenceUsage: true,
	}

	return cmd
}

// cliSecretSet sets one or more secrets using a secrets manifest
func cliSecretSet(host string, newSecrets []byte, clCert tls.Certificate, caCert []*pem.Block) error {
	client, err := restClient(caCert, &clCert)
	if err != nil {
		return err
	}

	url := url.URL{Scheme: "https", Host: host, Path: "secrets"}
	resp, err := client.Post(url.String(), "application/json", bytes.NewReader(newSecrets))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Everything went fine, just print the sucess message
		fmt.Println("Secret successfully set")
	case http.StatusBadRequest:
		// Something went wrong
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		response := gjson.GetBytes(respBody, "message")
		return fmt.Errorf("unable to set secret: %s", response)
	case http.StatusUnauthorized:
		// User was not authorized
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		response := gjson.GetBytes(respBody, "message")
		return fmt.Errorf("unable to authorize user: %s", response)
	default:
		return fmt.Errorf("error connecting to server: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return nil
}
