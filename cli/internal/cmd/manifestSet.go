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

func runManifestSet(cmd *cobra.Command, args []string) (retErr error) {
	manifestFile := args[0]
	hostname := args[1]
	fs := afero.NewOsFs()

	recoveryFilename, err := cmd.Flags().GetString("recoverydata")
	if err != nil {
		return err
	}

	verifyOpts, sgxQuotePath, err := parseRestFlags(cmd)
	if err != nil {
		return err
	}

	root, intermediate, sgxQuote, err := api.VerifyCoordinator(cmd.Context(), hostname, verifyOpts)
	if err != nil {
		return err
	}
	cmd.Println("Successfully verified Coordinator, now uploading manifest")

	manifest, err := loadManifestFile(file.New(manifestFile, fs))
	if err != nil {
		return err
	}
	signature := cliManifestSignature(manifest)
	cmd.Printf("Manifest signature: %s\n", signature)

	manifestSet := func(ctx context.Context) (map[string][]byte, error) {
		return api.ManifestSet(ctx, hostname, root, manifest)
	}
	if err := cliManifestSet(cmd, file.New(recoveryFilename, afero.NewOsFs()), manifestSet); err != nil {
		return err
	}

	if err := saveSgxQuote(fs, sgxQuote, sgxQuotePath); err != nil {
		return err
	}
	// Save the certificate of this Coordinator instance to disk
	return certcache.SaveCoordinatorCachedCert(cmd.Flags(), fs, root, intermediate)
}

// cliManifestSet sets the Coordinators manifest using its rest api.
func cliManifestSet(
	cmd *cobra.Command, recFile *file.Handler,
	setManifest func(context.Context) (map[string][]byte, error),
) error {
	recoveryData, err := setManifest(cmd.Context())
	if err != nil {
		return fmt.Errorf("setting manifest: %w", err)
	}
	cmd.Println("Manifest successfully set")

	// Skip outputting secrets if we do not get any recovery secrets back
	if len(recoveryData) == 0 {
		return nil
	}

	// recovery secret was sent, print or save to file
	wrappedRecoveryData := struct {
		RecoverySecrets map[string][]byte `json:"RecoverySecrets"`
	}{
		RecoverySecrets: recoveryData,
	}
	recoveryDataJSON, err := json.Marshal(wrappedRecoveryData)
	if err != nil {
		return fmt.Errorf("marshalling recovery data: %w", err)
	}
	if recFile != nil {
		if err := recFile.Write(recoveryDataJSON, file.OptOverwrite); err != nil {
			return err
		}
		cmd.Printf("Recovery data saved to: %s\n", recFile.Name())
	} else {
		cmd.Println(string(recoveryDataJSON))
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
