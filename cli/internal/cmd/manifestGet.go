// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
)

func newManifestGet() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <IP:PORT>",
		Short: "Get the manifest from the MarbleRun Coordinator",
		Long: `Get the manifest from the MarbleRun Coordinator.
Optionally get the manifests signature or merge updates into the displayed manifest.`,
		Example: "marblerun manifest get $MARBLERUN -s --era-config=era.json",
		Args:    cobra.ExactArgs(1),
		RunE:    runManifestGet,
	}

	cmd.Flags().BoolP("signature", "s", false, "Set to additionally display the manifests signature")
	cmd.Flags().BoolP("display-update", "u", false, "Set to merge updates into the displayed manifest")
	cmd.Flags().StringP("output", "o", "", "Save output to file instead of printing to stdout")
	return cmd
}

func runManifestGet(cmd *cobra.Command, args []string) error {
	hostname := args[0]
	client, err := rest.NewClient(cmd, hostname)
	if err != nil {
		return err
	}
	cmd.Println("Successfully verified Coordinator, now requesting manifest")

	flags, err := parseManifestGetFlags(cmd)
	if err != nil {
		return err
	}
	file := file.New(flags.output, afero.NewOsFs())

	return cliManifestGet(cmd, flags, file, client)
}

func cliManifestGet(cmd *cobra.Command, flags manifestGetFlags, file *file.Handler, client getter) error {
	resp, err := client.Get(cmd.Context(), rest.ManifestEndpoint, http.NoBody)
	if err != nil {
		return fmt.Errorf("getting manifest: %w", err)
	}

	manifest, err := decodeManifest(cmd.Context(), flags.displayUpdate, gjson.GetBytes(resp, "Manifest").String(), client)
	if err != nil {
		return err
	}
	if flags.signature {
		// wrap the signature and manifest into one json object
		manifest = fmt.Sprintf("{\n\"ManifestSignature\": \"%s\",\n\"Manifest\": %s}", gjson.GetBytes(resp, "ManifestSignature"), manifest)
	}

	if file != nil {
		return file.Write([]byte(manifest))
	}
	cmd.Println(manifest)
	return nil
}

// decodeManifest parses a base64 encoded manifest and optionally merges updates.
func decodeManifest(ctx context.Context, displayUpdate bool, encodedManifest string, client getter) (string, error) {
	manifest, err := base64.StdEncoding.DecodeString(encodedManifest)
	if err != nil {
		return "", err
	}

	if !displayUpdate {
		return string(manifest), nil
	}

	log, err := client.Get(ctx, rest.UpdateEndpoint, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("retrieving update log: %w", err)
	}
	return consolidateManifest(manifest, log)
}

// consolidateManifest updates a base manifest with values from an update log.
func consolidateManifest(rawManifest, log []byte) (string, error) {
	var baseManifest manifest.Manifest
	if err := json.Unmarshal(rawManifest, &baseManifest); err != nil {
		return "", err
	}

	pkg := gjson.GetBytes(log, "..#.package").Array()
	svn := gjson.GetBytes(log, "..#.new version").Array()
	for idx, sPkg := range pkg {
		*baseManifest.Packages[sPkg.String()].SecurityVersion = uint(svn[idx].Uint())
	}

	updated, err := json.Marshal(baseManifest)
	if err != nil {
		return "", err
	}
	var removeTarget map[string]interface{}
	if err := json.Unmarshal(updated, &removeTarget); err != nil {
		return "", err
	}
	removeNil(removeTarget)
	updated, err = json.Marshal(removeTarget)
	if err != nil {
		return "", err
	}

	return gjson.Parse(string(updated)).Get(`@pretty:{"indent":"    "}`).String(), nil
}

// removeNil removes nil entries from a map.
func removeNil(m map[string]interface{}) {
	for k, v := range m {
		// remove key if value is nil
		if v == nil {
			delete(m, k)
			continue
		}

		switch t := v.(type) {
		case map[string]interface{}:
			// recursively remove nil keys from the map
			removeNil(t)
			// if the current key maps to an empty map remove it
			if len(t) == 0 {
				delete(m, k)
			}
		}
	}
}

type manifestGetFlags struct {
	output        string
	displayUpdate bool
	signature     bool
}

func parseManifestGetFlags(cmd *cobra.Command) (manifestGetFlags, error) {
	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return manifestGetFlags{}, err
	}
	displayUpdate, err := cmd.Flags().GetBool("display-update")
	if err != nil {
		return manifestGetFlags{}, err
	}
	signature, err := cmd.Flags().GetBool("signature")
	if err != nil {
		return manifestGetFlags{}, err
	}
	return manifestGetFlags{
		output:        output,
		displayUpdate: displayUpdate,
		signature:     signature,
	}, nil
}
