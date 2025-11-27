/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"fmt"

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/util"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

func newRecoverSignSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign-secret <recovery_key_file>",
		Short: "Sign a recovery secret using the recovery private key",
		Long: "Sign a recovery secret using the recovery private key.\n" +
			"`recovery_key_file` may be either a decrypted recovery secret, or an encrypted recovery secret,\n" +
			"in which case the private key is used to decrypt the secret.",
		RunE: runRecoverSign,
		Args: cobra.ExactArgs(1),
	}

	cmd.Flags().StringP("output", "o", "", "File to save the signature to")
	cmd.Flags().StringP("key", "k", "", "Path to a recovery private key to decrypt and/or sign the recovery key")
	cmd.Flags().String("pkcs11-config", "", "Path to a PKCS#11 configuration file to load the recovery private key with")
	cmd.Flags().String("pkcs11-key-id", "", "ID of the private key in the PKCS#11 token")
	cmd.Flags().String("pkcs11-key-label", "", "Label of the private key in the PKCS#11 token")
	must(cobra.MarkFlagFilename(cmd.Flags(), "pkcs11-config", "json"))
	cmd.MarkFlagsOneRequired("pkcs11-key-id", "pkcs11-key-label", "key")
	cmd.MarkFlagsMutuallyExclusive("pkcs11-config", "key")
	must(cmd.MarkFlagRequired("output"))

	return cmd
}

func runRecoverSign(cmd *cobra.Command, args []string) error {
	keyFile := args[0]
	fs := afero.NewOsFs()

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	sigFile := file.New(output, fs)

	recoveryKey, err := file.New(keyFile, fs).Read()
	if err != nil {
		return err
	}

	keyHandle, cancel, err := getRecoveryKeyHandle(cmd, afero.Afero{Fs: fs})
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

	signature, err := util.SignPKCS1v15(keyHandle, recoveryKey)
	if err != nil {
		return err
	}

	if err := sigFile.Write(signature); err != nil {
		return fmt.Errorf("writing signature to file: %w", err)
	}
	return nil
}
