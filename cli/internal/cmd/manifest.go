/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"github.com/spf13/cobra"
)

// NewManifestCmd returns the manifest command.
func NewManifestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manifest",
		Short: "Manages manifest for the MarbleRun Coordinator",
		Long: `
Manages manifests for the MarbleRun Coordinator.
Used to either set the manifest, update an already set manifest,
or return a signature of the currently set manifest to the user`,
		Example: "manifest set manifest.json example.com:4433 [--era-config=config.json] [--insecure]",
	}

	cmd.AddCommand(newManifestGet())
	cmd.AddCommand(newManifestLog())
	cmd.AddCommand(newManifestSet())
	cmd.AddCommand(newManifestSignature())
	cmd.AddCommand(newManifestUpdate())
	cmd.AddCommand(newManifestVerify())

	return cmd
}
