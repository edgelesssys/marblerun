// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

func newSecretSet() *cobra.Command {
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
		Example: `# Set a secret from a JSON file
marblerun secret set secret.json $MARBLERUN -c admin.crt -k admin.key

# Set a secret from a PEM encoded file
marblerun secret set certificate.pem $MARBLERUN -c admin.crt -k admin.key --from-pem certificateSecret`,
		Args: cobra.ExactArgs(2),
		RunE: runSecretSet,
	}

	cmd.Flags().String("from-pem", "", "name of the secret from a PEM encoded file")

	return cmd
}

func runSecretSet(cmd *cobra.Command, args []string) error {
	secretFile := args[0]
	hostname := args[1]

	fromPem, err := cmd.Flags().GetString("from-pem")
	if err != nil {
		return err
	}

	newSecrets, err := file.New(secretFile, afero.NewOsFs()).Read()
	if err != nil {
		return err
	}

	if fromPem != "" {
		newSecrets, err = createSecretFromPEM(fromPem, newSecrets)
		if err != nil {
			return err
		}
	}

	client, err := rest.NewAuthenticatedClient(cmd, hostname)
	if err != nil {
		return err
	}

	return cliSecretSet(cmd, newSecrets, client)
}

// cliSecretSet sets one or more secrets using a secrets manifest.
func cliSecretSet(cmd *cobra.Command, newSecrets []byte, client poster) error {
	_, err := client.Post(cmd.Context(), rest.SecretEndpoint, rest.ContentJSON, bytes.NewReader(newSecrets))
	if err != nil {
		return fmt.Errorf("setting secret: %w", err)
	}

	cmd.Println("Secret successfully set")
	return nil
}

// createSecretFromPEM creates a JSON string from a certificate and/or private key in PEM format.
// If the PEM data contains more than one cert of key only the first instance will be part of the secret.
func createSecretFromPEM(secretName string, rawPEM []byte) ([]byte, error) {
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
