// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
)

func newManifestVerify() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <manifest/signature> <IP:PORT>",
		Short: "Verifies the signature of a MarbleRun manifest",
		Long:  `Verifies that the signature returned by the Coordinator is equal to a local signature`,
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			manifest := args[0]
			hostName := args[1]

			cert, err := verifyCoordinator(hostName, eraConfig, insecureEra)
			if err != nil {
				return err
			}

			localSignature, err := getSignatureFromString(manifest)
			if err != nil {
				return err
			}

			return cliManifestVerify(localSignature, hostName, cert)
		},
		SilenceUsage: true,
	}

	return cmd
}

// getSignatureFromString checks if a string is a file or a valid signature.
func getSignatureFromString(manifest string) (string, error) {
	if _, err := os.Stat(manifest); err != nil {
		if !os.IsNotExist(err) {
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
	rawManifest, err := ioutil.ReadFile(manifest)
	if err != nil {
		return "", err
	}
	return cliManifestSignature(rawManifest), nil
}

// cliManifestVerify verifies if a signature returned by the MarbleRun Coordinator is equal to one locally created.
func cliManifestVerify(localSignature string, host string, cert []*pem.Block) error {
	remoteSignature, err := cliDataGet(host, "manifest", "data.ManifestSignature", cert)
	if err != nil {
		return err
	}

	if string(remoteSignature) != localSignature {
		return fmt.Errorf("remote signature differs from local signature: %s != %s", string(remoteSignature), localSignature)
	}

	fmt.Println("OK")
	return nil
}
