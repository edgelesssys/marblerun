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

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
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

	manifest, err := loadManifestFile(file.New(manifestFile, afero.NewOsFs()))
	if err != nil {
		return err
	}
	signature := cliManifestSignature(manifest)
	cmd.Printf("Manifest signature: %s\n", signature)

	return cliManifestSet(cmd, manifest, file.New(recoveryFilename, afero.NewOsFs()), client)
}

// cliManifestSet sets the Coordinators manifest using its rest api.
func cliManifestSet(cmd *cobra.Command, manifest []byte, file *file.Handler, client poster) error {
	resp, err := client.Post(cmd.Context(), rest.ManifestEndpoint, rest.ContentJSON, bytes.NewReader(manifest))
	if err != nil {
		return fmt.Errorf("setting manifest: %w", err)
	}
	cmd.Println("Manifest successfully set")

	// Skip outputting secrets if we do not get any recovery secrets back
	if len(resp) == 0 {
		return nil
	}
	// recovery secret was sent, print or save to file
	if file != nil {
		if err := file.Write(resp); err != nil {
			return err
		}
		cmd.Printf("Recovery data saved to: %s\n", file.Name())
	} else {
		cmd.Println(string(resp))
	}

	return nil
}

// loadManifestFile loads a manifest in either json or yaml format and returns the data as json.
func loadManifestFile(file *file.Handler) ([]byte, error) {
	manifestData, err := file.Read()
	if err != nil {
		return nil, err
	}

	// if Valid is true the file was in JSON format and we can just return the data
	if json.Valid(manifestData) {
		return manifestData, nil
	}

	// otherwise we try to convert from YAML to json
	return yaml.YAMLToJSONStrict(manifestData)
}
