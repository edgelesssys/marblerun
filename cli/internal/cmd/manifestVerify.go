/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/edgelesssys/marblerun/api"
	"github.com/edgelesssys/marblerun/cli/internal/certcache"
	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
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

	verifyOpts, sgxQuotePath, err := parseRestFlags(cmd)
	if err != nil {
		return err
	}
	root, intermediate, sgxQuote, err := api.VerifyMarbleRunDeployment(cmd.Context(), hostname, verifyOpts, localSignature)
	if err != nil {
		return err
	}
	cmd.Println("OK")

	if err := saveSgxQuote(fs, sgxQuote, sgxQuotePath); err != nil {
		return err
	}
	return certcache.SaveCoordinatorCachedCert(cmd.Flags(), fs, root, intermediate)
}

// getSignatureFromString checks if a string is a file or a valid signature.
// If the string is a file, it returns the signature of the file (sha256 hash),
// otherwise it returns the decoded signature.
func getSignatureFromString(manifest string, fs afero.Fs) ([]byte, error) {
	if _, err := fs.Stat(manifest); err != nil {
		if !errors.Is(err, afero.ErrFileNotFound) {
			return nil, err
		}

		// command was called with a string that is not an existing file
		// check if the string could be a valid signature
		if len(manifest) != hex.EncodedLen(sha256.Size) {
			return nil, fmt.Errorf("%s is not a file and of invalid length to be a signature (needs to be 32 bytes)", manifest)
		}
		manifestHash, err := hex.DecodeString(manifest)
		if err != nil {
			return nil, fmt.Errorf("%s is not a file and not a valid signature (needs to be in hex format)", manifest)
		}
		return manifestHash, nil
	}

	// manifest is an existing file -> return the signature of the file
	rawManifest, err := loadManifestFile(file.New(manifest, fs))
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(cliManifestSignature(rawManifest))
}
