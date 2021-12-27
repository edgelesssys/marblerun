package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
)

func newSecretSet() *cobra.Command {
	var pemSecretName string

	cmd := &cobra.Command{
		Use:   "set <secret_file> <IP:PORT>",
		Short: "Set a secret for the MarbleRun Coordinator",
		Long: `
Set a secret for the MarbleRun Coordinator.
Secrets are loaded from a file in JSON format or directly from a PEM
encoded certificate and/or key. In the later case, the name of the secret
has to be set with the flag [--from-pem].
Users have to authenticate themselves using a certificate and private key
and need permissions in the manifest to write the requested secrets.
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

			if len(pemSecretName) > 0 {
				newSecrets, err = loadSecretFromPEM(pemSecretName, newSecrets)
				if err != nil {
					return err
				}
			}

			return cliSecretSet(hostName, newSecrets, clCert, caCert)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&pemSecretName, "from-pem", "", "name of the secret from a PEM encoded file")

	return cmd
}

// cliSecretSet sets one or more secrets using a secrets manifest.
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
		// Everything went fine, just print the success message
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

// loadSecretFromPEM creates a JSON string from a certificate and/or private key in PEM format.
// If the PEM data contains more than one cert of key only the first instance will be part of the secret.
func loadSecretFromPEM(secretName string, rawPEM []byte) ([]byte, error) {
	newSecret := manifest.UserSecret{}
	for {
		block, rest := pem.Decode(rawPEM)
		// stop if no more PEM data is found or if we already have cert and key
		if block == nil || (len(newSecret.Cert.Raw) > 0 && len(newSecret.Private) > 0) {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			newSecret.Cert = manifest.Certificate(*cert)
		} else if strings.Contains(block.Type, "PRIVATE") {
			newSecret.Private = block.Bytes
		} else {
			return nil, fmt.Errorf("unrecognized PEM type for secret: %s", block.Type)
		}
		rawPEM = rest
	}

	// error if neither cert nor key was found
	if len(newSecret.Cert.Raw) <= 0 && len(newSecret.Private) <= 0 {
		return nil, fmt.Errorf("found no certificate or private key in PEM data")
	}

	wrapped := map[string]manifest.UserSecret{
		secretName: newSecret,
	}
	return json.Marshal(wrapped)
}
