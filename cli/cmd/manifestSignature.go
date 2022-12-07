// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
)

func newManifestSignature() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signature <manifest.json>",
		Short: "Prints the signature of a MarbleRun manifest",
		Long:  "Prints the signature of a MarbleRun manifest",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			manifestFile := args[0]

			// Load manifest
			manifest, err := loadManifestFile(manifestFile)
			if err != nil {
				return err
			}

			signature := cliManifestSignature(manifest)
			fmt.Printf("%s\n", signature)
			return nil
		},
		SilenceUsage: true,
	}

	return cmd
}

func cliManifestSignature(rawManifest []byte) string {
	hash := sha256.Sum256(rawManifest)
	return hex.EncodeToString(hash[:])
}
