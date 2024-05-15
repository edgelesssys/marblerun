// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/edgelesssys/marblerun/api"
	"github.com/edgelesssys/marblerun/cli/internal/certcache"
	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

func newSecretGet() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get SECRETNAME ... <IP:PORT>",
		Short: "Retrieve secrets from the MarbleRun Coordinator",
		Long: `
Retrieve one or more secrets from the MarbleRun Coordinator.
Users have to authenticate themselves using a certificate and private key,
and need permissions in the manifest to read the requested secrets.
`,
		Example: "marblerun secret get genericSecret symmetricKeyShared $MARBLERUN -c admin.crt -k admin.key",
		Args:    cobra.MinimumNArgs(2),
		RunE:    runSecretGet,
	}

	cmd.Flags().StringP("output", "o", "", "File to save the secret to")

	return cmd
}

func runSecretGet(cmd *cobra.Command, args []string) error {
	hostname := args[len(args)-1]
	secretIDs := args[0 : len(args)-1]
	fs := afero.NewOsFs()

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}

	root, _, err := certcache.LoadCoordinatorCachedCert(cmd.Flags(), fs)
	if err != nil {
		return err
	}
	keyPair, err := certcache.LoadClientCert(cmd.Flags())
	if err != nil {
		return err
	}

	getSecrets := func(ctx context.Context) (map[string]manifest.Secret, error) {
		return api.SecretGet(ctx, hostname, root, keyPair, secretIDs)
	}
	return cliSecretGet(cmd, file.New(output, fs), getSecrets)
}

// cliSecretGet requests one or more secrets from the MarbleRun Coordinator.
func cliSecretGet(
	cmd *cobra.Command, secFile *file.Handler,
	getSecrets func(context.Context) (map[string]manifest.Secret, error),
) error {
	secrets, err := getSecrets(cmd.Context())
	if err != nil {
		return fmt.Errorf("retrieving secrets: %w", err)
	}

	if secFile == nil {
		return printSecrets(cmd.OutOrStdout(), secrets)
	}

	secretsJSON, err := json.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("marshalling secrets: %w", err)
	}
	if err := secFile.Write(secretsJSON, file.OptOverwrite); err != nil {
		return err
	}
	cmd.Printf("Saved secrets to: %s\n", secFile.Name())

	return nil
}

// printSecrets prints secrets formatted in a readable way.
func printSecrets(out io.Writer, secrets map[string]manifest.Secret) error {
	for name, secret := range secrets {
		fmt.Fprintf(out, "%s:\n", name)
		var output string
		output = prettyFormat(output, "Type:", secret.Type)

		switch secret.Type {
		case manifest.SecretTypeCertRSA, manifest.SecretTypeCertECDSA, manifest.SecretTypeCertED25519:
			output = prettyFormat(output, "UserDefined:", secret.UserDefined)

			if secret.Type == manifest.SecretTypeCertRSA || secret.Type == manifest.SecretTypeCertECDSA {
				output = prettyFormat(output, "Size:", secret.Size)
			}

			output = prettyFormat(output, "Valid For:", secret.ValidFor)
			output = prettyFormat(output, "Certificate:", secret.Cert)
			output = prettyFormat(output, "Public Key:", secret.Public)
			output = prettyFormat(output, "Private Key:", secret.Private)
		case manifest.SecretTypeSymmetricKey:
			output = prettyFormat(output, "UserDefined:", secret.UserDefined)
			output = prettyFormat(output, "Size:", secret.Size)
			output = prettyFormat(output, "Key:", secret.Public)
		case manifest.SecretTypePlain:
			output = prettyFormat(output, "Data:", secret.Public)
		default:
			return fmt.Errorf("unknown secret type")
		}
		fmt.Fprintf(out, "%s\n", output)
	}
	return nil
}

func prettyFormat(previous, label, value any) string {
	return fmt.Sprintf("%s\t%-14s %v\n", previous, label, value)
}
