// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
)

type secretGetOptions struct {
	host      string
	secretIDs []string
	output    string
	clCert    tls.Certificate
	caCert    []*pem.Block
}

func newSecretGet() *cobra.Command {
	options := &secretGetOptions{}

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
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[len(args)-1]
			caCert, err := verifyCoordinator(cmd.OutOrStdout(), hostName, eraConfig, insecureEra, acceptedTCBStatuses)
			if err != nil {
				return err
			}

			// Load client certificate and key
			clCert, err := tls.LoadX509KeyPair(userCertFile, userKeyFile)
			if err != nil {
				return err
			}

			options.secretIDs = args[0 : len(args)-1]
			options.host = hostName
			options.caCert = caCert
			options.clCert = clCert

			return cliSecretGet(cmd.OutOrStdout(), options)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&options.output, "output", "o", "", "File to save the secret to")

	return cmd
}

// cliSecretGet requests one or more secrets from the MarbleRun Coordinator.
func cliSecretGet(out io.Writer, o *secretGetOptions) error {
	client, err := restClient(o.caCert, &o.clCert)
	if err != nil {
		return err
	}

	secretQuery := url.Values{}

	for _, secret := range o.secretIDs {
		secretQuery.Add("s", secret)
	}
	url := url.URL{Scheme: "https", Host: o.host, Path: "secrets", RawQuery: secretQuery.Encode()}
	resp, err := client.Get(url.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Everything went fine, print the secret or save to file
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		response := gjson.GetBytes(respBody, "data")
		if len(response.String()) <= 0 {
			return fmt.Errorf("received empty secret response")
		}

		if len(response.Map()) != len(o.secretIDs) {
			return fmt.Errorf("did not receive the same number of secrets as requested")
		}

		if o.output == "" {
			return printSecrets(out, response)
		}
		if err := ioutil.WriteFile(o.output, []byte(response.String()), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(out, "Saved secret to: %s\n", o.output)
	case http.StatusBadRequest:
		// Something went wrong
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		response := gjson.GetBytes(respBody, "message")
		return fmt.Errorf("unable to retrieve secret: %s", response)
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
