// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
	"sigs.k8s.io/yaml"
)

func newManifestSet() *cobra.Command {
	var recoveryFilename string

	cmd := &cobra.Command{
		Use:     "set <manifest.json> <IP:PORT>",
		Short:   "Sets the manifest for the MarbleRun Coordinator",
		Long:    "Sets the manifest for the MarbleRun Coordinator",
		Example: "marblerun manifest set manifest.json $MARBLERUN --recovery-data=recovery-secret.json --era-config=era.json",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			manifestFile := args[0]
			hostName := args[1]

			cert, err := verifyCoordinator(cmd.OutOrStdout(), hostName, eraConfig, insecureEra, acceptedTCBStatuses)
			if err != nil {
				return err
			}

			cmd.Println("Successfully verified Coordinator, now uploading manifest")

			// Load manifest
			manifest, err := loadManifestFile(manifestFile)
			if err != nil {
				return err
			}
			signature := cliManifestSignature(manifest)
			cmd.Printf("Manifest signature: %s\n", signature)

			return cliManifestSet(cmd.OutOrStdout(), manifest, hostName, cert, recoveryFilename)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&recoveryFilename, "recoverydata", "r", "", "File to write recovery data to, print to stdout if non specified")

	return cmd
}

// cliManifestSet sets the Coordinators manifest using its rest api.
func cliManifestSet(out io.Writer, manifest []byte, host string, cert []*pem.Block, recover string) error {
	client, err := restClient(cert, nil)
	if err != nil {
		return err
	}

	url := url.URL{Scheme: "https", Host: host, Path: "manifest"}
	resp, err := client.Post(url.String(), "application/json", bytes.NewReader(manifest))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, "Manifest successfully set")

		if len(respBody) <= 0 {
			return nil
		}

		response := gjson.GetBytes(respBody, "data")

		// Skip outputting secrets if we do not get any recovery secrets back
		if len(response.String()) == 0 {
			return nil
		}

		// recovery secret was sent, print or save to file
		if recover == "" {
			fmt.Fprintln(out, response.String())
		} else {
			if err := ioutil.WriteFile(recover, []byte(response.String()), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(out, "Recovery data saved to: %s.\n", recover)
		}
	case http.StatusBadRequest:
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		response := gjson.GetBytes(respBody, "message")
		return fmt.Errorf(response.String())
	default:
		return fmt.Errorf("error connecting to server: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return nil
}

// loadManifestFile loads a manifest in either json or yaml format and returns the data as json.
func loadManifestFile(filename string) ([]byte, error) {
	manifestData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// if Valid is true the file was in JSON format and we can just return the data
	if json.Valid(manifestData) {
		return manifestData, err
	}

	// otherwise we try to convert from YAML to json
	return yaml.YAMLToJSON(manifestData)
}
