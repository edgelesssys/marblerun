// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
)

func newManifestVerify() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "verify <manifest/signature> <IP:PORT>",
		Short:   "Verify the signature of a MarbleRun manifest",
		Long:    `Verify that the signature returned by the Coordinator is equal to a local signature`,
		Example: "marblerun manifest verify manifest.json $MARBLERUN",
		Args:    cobra.ExactArgs(2),
		RunE:    runManifestVerify,
	}

	return cmd
}

func runManifestVerify(cmd *cobra.Command, args []string) error {
	manifest := args[0]
	hostname := args[1]

	localSignature, err := getSignatureFromString(manifest, afero.Afero{Fs: afero.NewOsFs()})
	if err != nil {
		return err
	}

	client, err := rest.NewClient(cmd, hostname)
	if err != nil {
		return err
	}
	return cliManifestVerify(cmd, localSignature, client)
}

// getSignatureFromString checks if a string is a file or a valid signature.
func getSignatureFromString(manifest string, fs afero.Afero) (string, error) {
	if _, err := fs.Stat(manifest); err != nil {
		if !errors.Is(err, afero.ErrFileNotFound) {
			return "", err
		}

		// command was called with a string that is not an existing file
		// check if the string could be a valid signature
		if len(manifest) != hex.EncodedLen(sha256.Size) {
			return "", fmt.Errorf("%s is not a file and of invalid length to be a signature (needs to be 32 bytes)", manifest)
		}
		if _, err := hex.DecodeString(manifest); err != nil {
			return "", fmt.Errorf("%s is not a file and not a valid signature (needs to be in hex format)", manifest)
		}
		return manifest, nil
	}

	// manifest is an existing file -> return the signature of the file
	rawManifest, err := loadManifestFile(file.New(manifest, fs))
	if err != nil {
		return "", err
	}
	return cliManifestSignature(rawManifest), nil
}

// cliManifestVerify verifies if a signature returned by the MarbleRun Coordinator is equal to one locally created.
func cliManifestVerify(cmd *cobra.Command, localSignature string, client getter) error {
	resp, err := client.Get(cmd.Context(), rest.ManifestEndpoint, http.NoBody)
	if err != nil {
		return err
	}
	remoteSignature := gjson.GetBytes(resp, "ManifestSignature").String()
	if remoteSignature != localSignature {
		return fmt.Errorf("remote signature differs from local signature: %s != %s", remoteSignature, localSignature)
	}

	cmd.Println("OK")
	return nil
}
