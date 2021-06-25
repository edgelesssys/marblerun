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
		Short: "Verifies the signature of a Marblerun manifest",
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

// getSignatureFromString checks if a string is a file or a valid signature
func getSignatureFromString(manifest string) (string, error) {
	_, err := os.Stat(manifest)
	if err != nil {
		if os.IsNotExist(err) {
			// command was called with a string that is not an existing file
			// check if the string could be a valid signature
			if len(manifest) != hex.EncodedLen(sha256.Size) {
				return "", fmt.Errorf("%s is not a file and of invalid length to be a signature (needs to be 32 bytes)", manifest)
			}
			if _, err := hex.DecodeString(manifest); err != nil {
				return "", fmt.Errorf("%s is not a file and not a valid signature (needs to be in hex format)", manifest)
			}
			return manifest, nil
		} else {
			return "", err
		}
	}

	// manifest is an existing file -> return the signature of the file
	rawManifest, err := ioutil.ReadFile(manifest)
	if err != nil {
		return "", err
	}
	return cliManifestSignature(rawManifest), nil
}

// cliManifestVerify verifies if a signature returned by the Marblerun Coordinator is equal to one locally created
func cliManifestVerify(localSignature string, host string, cert []*pem.Block) error {
	remoteSignature, err := cliManifestGet(host, "manifest", cert)
	if err != nil {
		return err
	}

	if string(remoteSignature) != localSignature {
		return fmt.Errorf("remote signature differs from local signature: %s != %s", string(remoteSignature), localSignature)
	}

	fmt.Println("OK")
	return nil
}
