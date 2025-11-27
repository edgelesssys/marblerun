/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"github.com/edgelesssys/marblerun/api"
	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

// NewRecoverWithSigCmd returns the recover-with-signature command.
func NewRecoverWithSigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recover-with-signature <recovery_key_file> <IP:PORT>",
		Short: "Recover the MarbleRun Coordinator from a sealed state",
		Long: "Recover the MarbleRun Coordinator from a sealed state.\n" +
			"`recovery_key_file` may be either a decrypted recovery secret,\n" +
			"or a recovery secret encrypted with the Coordinator's ephemeral public key.",

		Example: "marblerun recover-with-signature recovery_key_file $MARBLERUN --signature recovery.sig",
		Args:    cobra.ExactArgs(2),
		RunE:    runRecoverWithSignature,
	}

	cmd.Flags().StringP("signature", "s", "", "Path to a signature of the recovery secret")
	must(cmd.MarkFlagRequired("signature"))

	cmd.AddCommand(newRecoverPublicKeyCmd())
	cmd.AddCommand(newRecoverEncryptSecretCmd())
	cmd.AddCommand(newRecoverSignSecretCmd())

	return cmd
}

func runRecoverWithSignature(cmd *cobra.Command, args []string) error {
	keyFile := args[0]
	hostname := args[1]
	fs := afero.NewOsFs()

	sigFile, err := cmd.Flags().GetString("signature")
	if err != nil {
		return err
	}
	signature, err := file.New(sigFile, fs).Read()
	if err != nil {
		return err
	}

	recoveryKey, err := file.New(keyFile, fs).Read()
	if err != nil {
		return err
	}

	verifyOpts, sgxQuotePath, err := parseRestFlags(cmd)
	if err != nil {
		return err
	}

	remaining, sgxQuote, err := api.RecoverWithSignature(cmd.Context(), hostname, verifyOpts, recoveryKey, signature)
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
