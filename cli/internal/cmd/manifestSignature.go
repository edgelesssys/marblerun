/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

func newManifestSignature() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signature <manifest.json>",
		Short: "Prints the signature of a MarbleRun manifest",
		Long:  "Prints the signature of a MarbleRun manifest",
		Args:  cobra.ExactArgs(1),
		RunE:  runManifestSignature,
	}

	return cmd
}

func runManifestSignature(cmd *cobra.Command, args []string) error {
	manifestFile := args[0]

	manifest, err := loadManifestFile(file.New(manifestFile, afero.NewOsFs()))
	if err != nil {
		return err
	}

	signature := cliManifestSignature(manifest)
	cmd.Println(signature)
	return nil
}

func cliManifestSignature(rawManifest []byte) string {
	hash := sha256.Sum256(rawManifest)
	return hex.EncodeToString(hash[:])
}
