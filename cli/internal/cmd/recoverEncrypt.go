/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/util"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

func newRecoverEncryptSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "encrypt-secret <recovery_key_file>",
		Short: "Encrypt a recovery secret with the Coordinator's ephemeral public key",
		Long: "Encrypt a recovery secret with the Coordinator's ephemeral public key.\n" +
			"`recovery_key_file` may be either a decrypted recovery secret, or an encrypted recovery secret,\n" +
			"in which case a private key is required to decrypt the secret.",
		RunE: runRecoverEncryptSecret,
		Args: cobra.ExactArgs(1),
	}

	cmd.Flags().StringP("output", "o", "", "File to save the encrypted secret to")
	cmd.Flags().String("coordinator-pub-key", "", "Path to the Coordinator's PEM encoded ephemeral public key to encrypt the recovery secret with")
	cmd.Flags().StringP("key", "k", "", "Path to a recovery private key to decrypt and/or sign the recovery key")
	cmd.Flags().String("pkcs11-config", "", "Path to a PKCS#11 configuration file to load the recovery private key with")
	cmd.Flags().String("pkcs11-key-id", "", "ID of the private key in the PKCS#11 token")
	cmd.Flags().String("pkcs11-key-label", "", "Label of the private key in the PKCS#11 token")
	must(cobra.MarkFlagFilename(cmd.Flags(), "pkcs11-config", "json"))
	must(cobra.MarkFlagFilename(cmd.Flags(), "coordinator-pub-key", "pem"))
	cmd.MarkFlagsMutuallyExclusive("pkcs11-config", "key")
	must(cmd.MarkFlagRequired("coordinator-pub-key"))

	return cmd
}

func runRecoverEncryptSecret(cmd *cobra.Command, args []string) error {
	keyFile := args[0]
	fs := afero.NewOsFs()

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}

	pubKeyFilePEM, err := cmd.Flags().GetString("coordinator-pub-key")
	if err != nil {
		return err
	}
	pubKeyPEM, err := file.New(pubKeyFilePEM, fs).Read()
	if err != nil {
		return err
	}
	pubKeyDER, _ := pem.Decode(pubKeyPEM)
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyDER.Bytes)
	if err != nil {
		return err
	}
	coordinatorPub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected RSA public key, got %T", pubKey)
	}

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

	encryptedSecret, err := util.EncryptOAEP(coordinatorPub, recoveryKey)
	if err != nil {
		return err
	}

	if output != "" {
		if err := file.New(output, fs).Write(encryptedSecret); err != nil {
			return fmt.Errorf("writing encrypted secret to file: %w", err)
		}
	} else {
		cmd.Printf("%s\n", encryptedSecret)
	}

	return nil
}
