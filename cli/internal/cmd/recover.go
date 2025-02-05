/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/edgelesssys/marblerun/api"
	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/cli/internal/pkcs11"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

// NewRecoverCmd returns the recover command.
func NewRecoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recover <recovery_key_file> <IP:PORT>",
		Short: "Recover the MarbleRun Coordinator from a sealed state",
		Long: "Recover the MarbleRun Coordinator from a sealed state.\n" +
			"`recovery_key_file` may be either a decrypted recovery secret, or an encrypted recovery secret,\n" +
			"in which case the private key is used to decrypt the secret.",
		Example: "marblerun recover recovery_key_file $MARBLERUN",
		Args:    cobra.ExactArgs(2),
		RunE:    runRecover,
	}

	cmd.Flags().StringP("key", "k", "", "Path to a the recovery private key to decrypt and/or sign the recovery key")
	cmd.Flags().String("pkcs11-config", "", "Path to a PKCS#11 configuration file to load the recovery private key with")
	cmd.Flags().String("pkcs11-key-id", "", "ID of the private key in the PKCS#11 token")
	cmd.Flags().String("pkcs11-key-label", "", "Label of the private key in the PKCS#11 token")
	must(cobra.MarkFlagFilename(cmd.Flags(), "pkcs11-config", "json"))
	cmd.MarkFlagsOneRequired("pkcs11-key-id", "pkcs11-key-label", "key")
	cmd.MarkFlagsMutuallyExclusive("pkcs11-config", "key")

	return cmd
}

func runRecover(cmd *cobra.Command, args []string) error {
	keyFile := args[0]
	hostname := args[1]
	fs := afero.NewOsFs()

	recoveryKey, err := file.New(keyFile, fs).Read()
	if err != nil {
		return err
	}

	verifyOpts, sgxQuotePath, err := parseRestFlags(cmd)
	if err != nil {
		return err
	}

	keyHandle, cancel, err := getRecoveryKeySigner(cmd, afero.Afero{Fs: fs})
	if err != nil {
		return err
	}
	defer func() {
		if err := cancel(); err != nil {
			cmd.PrintErrf("Failed to close PKCS #11 session: %s\n", err)
		}
	}()

	recoveryKey, err = maybeDecryptRecoveryKey(recoveryKey, keyHandle)
	if err != nil {
		return err
	}

	remaining, sgxQuote, err := api.Recover(cmd.Context(), hostname, verifyOpts, recoveryKey, keyHandle)
	if err != nil {
		return err
	}

	if remaining == 0 {
		cmd.Println("Recovery successful.")
	} else {
		cmd.Printf("Secret was processed successfully. Upload the next secret. Remaining secrets: %d\n", remaining)
	}

	if err := saveSgxQuote(fs, sgxQuote, sgxQuotePath); err != nil {
		return err
	}
	return nil
}

func getRecoveryKeySigner(cmd *cobra.Command, fs afero.Afero) (pkcs11.SignerDecrypter, func() error, error) {
	privKeyFile, err := cmd.Flags().GetString("key")
	if err != nil {
		return nil, nil, err
	}

	if privKeyFile == "" {
		pkcs11ConfigFile, err := cmd.Flags().GetString("pkcs11-config")
		if err != nil {
			return nil, nil, err
		}
		pkcs11KeyID, err := cmd.Flags().GetString("pkcs11-key-id")
		if err != nil {
			return nil, nil, err
		}
		pkcs11KeyLabel, err := cmd.Flags().GetString("pkcs11-key-label")
		if err != nil {
			return nil, nil, err
		}
		return pkcs11.LoadRSAPrivateKey(pkcs11ConfigFile, pkcs11KeyID, pkcs11KeyLabel)
	}

	privKeyPEM, err := fs.ReadFile(privKeyFile)
	if err != nil {
		return nil, nil, err
	}
	privateKeyBlock, _ := pem.Decode(privKeyPEM)
	if privateKeyBlock == nil {
		return nil, nil, fmt.Errorf("%q did not contain a valid PEM block", privKeyFile)
	}
	privK, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		// Try to parse as PKCS #1 private key as well
		var pkcs1Err error
		privK, pkcs1Err = x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
		if pkcs1Err != nil {
			return nil, nil, fmt.Errorf("parsing private key: tried PKCS #1 format: %w, tried PKCS #8 format: %w", pkcs1Err, err)
		}
	}
	signer, ok := privK.(pkcs11.SignerDecrypter)
	if !ok {
		return nil, nil, errors.New("loaded private key does not fulfill required interface")
	}
	return signer, func() error { return nil }, nil
}

// maybeDecryptRecoveryKey tries to decrypt the given recoveryKey using OAEP.
// If the recoveryKey is already 16 bytes long, it is returned as is.
func maybeDecryptRecoveryKey(recoveryKey []byte, decrypter crypto.Decrypter) ([]byte, error) {
	if len(recoveryKey) != 16 {
		return decrypter.Decrypt(rand.Reader, recoveryKey, &rsa.OAEPOptions{Hash: crypto.SHA256})
	}
	return recoveryKey, nil
}
