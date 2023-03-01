// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
	"sigs.k8s.io/yaml"
)

func newManifestSet() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "set <manifest.json> <IP:PORT>",
		Short:   "Sets the manifest for the MarbleRun Coordinator",
		Long:    "Sets the manifest for the MarbleRun Coordinator",
		Example: "marblerun manifest set manifest.json $MARBLERUN --recovery-data=recovery-secret.json --era-config=era.json",
		Args:    cobra.ExactArgs(2),
		RunE:    runManifestSet,
	}

	cmd.Flags().StringP("recoverydata", "r", "", "File to write recovery data to, print to stdout if non specified")

	return cmd
}

func runManifestSet(cmd *cobra.Command, args []string) error {
	manifestFile := args[0]
	hostname := args[1]

	recoveryFilename, err := cmd.Flags().GetString("recoverydata")
	if err != nil {
		return err
	}

	client, err := rest.NewClient(cmd, hostname)
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

	return cliManifestSet(cmd, manifest, recoveryFilename, client)
}

// cliManifestSet sets the Coordinators manifest using its rest api.
func cliManifestSet(cmd *cobra.Command, manifest []byte, recover string, client poster) error {
	resp, err := client.Post(cmd.Context(), "manifest", "application/json", bytes.NewReader(manifest))
	if err != nil {
		return fmt.Errorf("unable to set manifest: %w", err)
	}

	cmd.Println("Manifest successfully set")

	if len(resp) <= 0 {
		return nil
	}

	response := gjson.GetBytes(resp, "data")

	// Skip outputting secrets if we do not get any recovery secrets back
	if len(response.String()) == 0 {
		return nil
	}

	// recovery secret was sent, print or save to file
	if recover == "" {
		cmd.Println(response.String())
	} else {
		if err := os.WriteFile(recover, []byte(response.String()), 0o644); err != nil {
			return err
		}
		cmd.Printf("Recovery data saved to: %s.\n", recover)
	}

	return nil
}

// loadManifestFile loads a manifest in either json or yaml format and returns the data as json.
func loadManifestFile(filename string) ([]byte, error) {
	manifestData, err := os.ReadFile(filename)
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
