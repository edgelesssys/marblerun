// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"github.com/spf13/cobra"
)

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
