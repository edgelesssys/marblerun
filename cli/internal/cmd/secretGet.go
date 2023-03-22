// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"fmt"
	"io"
	"net/http"

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
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

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}

	client, err := rest.NewAuthenticatedClient(cmd, hostname)
	if err != nil {
		return err
	}

	return cliSecretGet(cmd, secretIDs, file.New(output, afero.NewOsFs()), client)
}

// cliSecretGet requests one or more secrets from the MarbleRun Coordinator.
func cliSecretGet(cmd *cobra.Command, secretIDs []string, file *file.Handler, client getter) error {
	var query []string
	for _, secretID := range secretIDs {
		query = append(query, "s", secretID)
	}

	resp, err := client.Get(cmd.Context(), rest.SecretEndpoint, http.NoBody, query...)
	if err != nil {
		return fmt.Errorf("retrieving secret: %w", err)
	}

	response := gjson.ParseBytes(resp)
	if len(response.Map()) != len(secretIDs) {
		return fmt.Errorf("did not receive the same number of secrets as requested")
	}

	if file == nil {
		return printSecrets(cmd.OutOrStdout(), response)
	}

	if err := file.Write([]byte(response.String())); err != nil {
		return err
	}
	cmd.Printf("Saved secrets to: %s\n", file.Name())

	return nil
}

// printSecrets prints secrets formatted in a readable way.
func printSecrets(out io.Writer, response gjson.Result) error {
	for secretName, singleResponse := range response.Map() {
		secretType := singleResponse.Get("Type")
		userDefined := singleResponse.Get("UserDefined")
		secretSize := singleResponse.Get("Size")
		validFor := singleResponse.Get("ValidFor")
		cert := singleResponse.Get("Cert")
		public := singleResponse.Get("Public")
		private := singleResponse.Get("Private")

		fmt.Fprintf(out, "%s:\n", secretName)
		var output string
		output = prettyFormat(output, "Type:", secretType.String())

		switch secretType.String() {
		case manifest.SecretTypeCertRSA, manifest.SecretTypeCertECDSA, manifest.SecretTypeCertED25519:
			output = prettyFormat(output, "UserDefined:", userDefined.String())
			if secretType.String() == manifest.SecretTypeCertRSA || secretType.String() == manifest.SecretTypeCertECDSA {
				output = prettyFormat(output, "Size:", secretSize.String())
			}
			output = prettyFormat(output, "Valid For:", validFor.String())
			output = prettyFormat(output, "Certificate:", cert.String())
			output = prettyFormat(output, "Public Key:", public.String())
			output = prettyFormat(output, "Private Key:", private.String())
		case manifest.SecretTypeSymmetricKey:
			output = prettyFormat(output, "UserDefined:", userDefined.String())
			output = prettyFormat(output, "Size:", secretSize.String())
			output = prettyFormat(output, "Key:", public.String())
		case manifest.SecretTypePlain:
			output = prettyFormat(output, "Data:", public.String())
		default:
			return fmt.Errorf("unknown secret type")
		}
		fmt.Fprintf(out, "%s\n", output)
	}
	return nil
}

func prettyFormat(previous, label, value string) string {
	return fmt.Sprintf("%s\t%-14s %s\n", previous, label, value)
}
