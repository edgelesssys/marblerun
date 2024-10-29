/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/edgelesssys/marblerun/api"
	"github.com/edgelesssys/marblerun/cli/internal/certcache"
	"github.com/edgelesssys/marblerun/cli/internal/file"
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

	cmd.Flags().Bool("keep-cert", false, "Set to keep the certificate of the Coordinator and save it to the location specified by --coordinator-cert")
	cmd.Flags().BoolP("signature", "s", false, "Set to additionally display the manifests signature")
	cmd.Flags().BoolP("display-update", "u", false, "Set to merge updates into the displayed manifest")
	cmd.Flags().StringP("output", "o", "", "Save output to file instead of printing to stdout")
	return cmd
}

func runManifestGet(cmd *cobra.Command, args []string) error {
	hostname := args[0]
	fs := afero.NewOsFs()

	verifyOpts, sgxQuotePath, err := parseRestFlags(cmd)
	if err != nil {
		return err
	}
	root, intermediate, sgxQuote, err := api.VerifyCoordinator(cmd.Context(), hostname, verifyOpts)
	if err != nil {
		return err
	}
	cmd.Println("Successfully verified Coordinator, now requesting manifest")

	flags, err := parseManifestGetFlags(cmd)
	if err != nil {
		return err
	}
	outFile := file.New(flags.output, fs)

	getManifest := func(ctx context.Context) (string, string, error) {
		mnf, hash, _, err := api.ManifestGet(ctx, hostname, root)
		return string(mnf), hash, err
	}
	getManifestLog := func(ctx context.Context) ([]string, error) {
		return api.ManifestLog(ctx, hostname, root)
	}
	if err := cliManifestGet(cmd, flags, outFile, getManifest, getManifestLog); err != nil {
		return err
	}

	if err := saveSgxQuote(fs, sgxQuote, sgxQuotePath); err != nil {
		return err
	}
	keep, err := cmd.Flags().GetBool("keep-cert")
	if err == nil && keep {
		return certcache.SaveCoordinatorCachedCert(cmd.Flags(), fs, root, intermediate)
	}
	return err
}

func cliManifestGet(
	cmd *cobra.Command, flags manifestGetFlags, mnfFile *file.Handler,
	getManifest func(context.Context) (string, string, error),
	getManifestLog func(context.Context) ([]string, error),
) error {
	manifest, hash, err := getManifest(cmd.Context())
	if err != nil {
		return fmt.Errorf("getting manifest: %w", err)
	}

	if flags.displayUpdate {
		updateLog, err := getManifestLog(cmd.Context())
		if err != nil {
			return fmt.Errorf("getting update log: %w", err)
		}
		manifest, err = consolidateManifest([]byte(manifest), updateLog)
		if err != nil {
			return fmt.Errorf("consolidating manifest: %w", err)
		}
	}

	if flags.signature {
		// wrap the signature and manifest into one json object
		manifest = fmt.Sprintf("{\n\"ManifestSignature\": \"%s\",\n\"Manifest\": %s}", hash, manifest)
	}

	if mnfFile != nil {
		return mnfFile.Write([]byte(manifest), file.OptOverwrite)
	}
	cmd.Println(manifest)
	return nil
}

// consolidateManifest updates a base manifest with values from an update log.
func consolidateManifest(rawManifest []byte, log []string) (string, error) {
	var baseManifest manifest.Manifest
	if err := json.Unmarshal(rawManifest, &baseManifest); err != nil {
		return "", err
	}

	for _, logEntry := range log {
		if gjson.Get(logEntry, "package").Exists() {
			pkg := gjson.Get(logEntry, "package").String()
			if _, ok := baseManifest.Packages[pkg]; !ok {
				return "", fmt.Errorf("package %s not found in base manifest", pkg)
			}

			if gjson.Get(logEntry, "new version").Exists() {
				*baseManifest.Packages[pkg].SecurityVersion = uint(gjson.Get(logEntry, "new version").Uint())
			}
		}
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
