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
	fs := afero.NewOsFs()

	localSignature, err := getSignatureFromString(manifest, fs)
	if err != nil {
		return err
	}

	restFlags, err := parseRestFlags(cmd.Flags())
	if err != nil {
		return err
	}
	caCert, err := rest.VerifyCoordinator(
		cmd.Context(), cmd.OutOrStdout(), hostname,
		restFlags.eraConfig, restFlags.k8sNamespace, restFlags.insecure, restFlags.acceptedTCBStatuses,
	)
	if err != nil {
		return err
	}

	client, err := rest.NewClient(hostname, caCert, nil, restFlags.insecure)
	if err != nil {
		return err
	}
	if err := cliManifestVerify(cmd, localSignature, client); err != nil {
		return err
	}

	return rest.SaveCoordinatorCachedCert(cmd.Flags(), fs, caCert)
}

// getSignatureFromString checks if a string is a file or a valid signature.
func getSignatureFromString(manifest string, fs afero.Fs) (string, error) {
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
