// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
)

func newManifestGet() *cobra.Command {
	var output string
	var displayUpdate bool
	var signature bool

	cmd := &cobra.Command{
		Use:   "get <IP:PORT>",
		Short: "Get the manifest from the MarbleRun Coordinator",
		Long: `Get the manifest from the MarbleRun Coordinator.
Optionally get the manifests signature or merge updates into the displayed manifest.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			cert, err := verifyCoordinator(hostName, eraConfig, insecureEra)
			if err != nil {
				return err
			}
			fmt.Println("Successfully verified Coordinator, now requesting manifest")
			response, err := cliDataGet(hostName, "manifest", "data", cert)
			if err != nil {
				return err
			}
			manifest, err := decodeManifest(displayUpdate, gjson.GetBytes(response, "Manifest").String(), hostName, cert)
			if err != nil {
				return err
			}
			if signature {
				// wrap the signature and manifest into one json object
				manifest = fmt.Sprintf("{\n\"ManifestSignature\": \"%s\",\n\"Manifest\": %s}", gjson.GetBytes(response, "ManifestSignature"), manifest)
			}

			if len(output) > 0 {
				return ioutil.WriteFile(output, []byte(manifest), 0o644)
			}
			fmt.Println(manifest)
			return nil
		},
		SilenceUsage: true,
	}

	cmd.Flags().BoolVarP(&signature, "signature", "s", false, "Set to additionally display the manifests signature")
	cmd.Flags().BoolVarP(&displayUpdate, "display-update", "u", false, "Set to merge updates into the displayed manifest")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Save output to file instead of printing to stdout")
	return cmd
}

// decodeManifest parses a base64 encoded manifest and optionally merges updates.
func decodeManifest(displayUpdate bool, encodedManifest, hostName string, cert []*pem.Block) (string, error) {
	manifest, err := base64.StdEncoding.DecodeString(encodedManifest)
	if err != nil {
		return "", err
	}

	if !displayUpdate {
		return string(manifest), nil
	}

	log, err := cliDataGet(hostName, "update", "data", cert)
	if err != nil {
		return "", err
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
