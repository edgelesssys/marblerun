/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/edgelesssys/marblerun/api"
	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

func newRecoverPublicKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "public-key <IP:PORT>",
		Short: "Retrieve the Coordinator's ephemeral public key for encrypting recovery secrets",
		Long:  "Retrieve the Coordinator's ephemeral public key for encrypting recovery secrets.",
		RunE:  runRecoverPublicKey,
		Args:  cobra.ExactArgs(1),
	}

	cmd.Flags().StringP("output", "o", "", "File to save the public key to")

	return cmd
}

func runRecoverPublicKey(cmd *cobra.Command, args []string) error {
	hostname := args[0]
	fs := afero.NewOsFs()

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	pubFile := file.New(output, fs)

	verifyOpts, sgxQuotePath, err := parseRestFlags(cmd)
	if err != nil {
		return err
	}

	pubKey, sgxQuote, err := api.RecoveryPublicKey(cmd.Context(), hostname, verifyOpts)
	if err != nil {
		return fmt.Errorf("retrieving recovery public key: %w", err)
	}

	pubKeyDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("marshalling public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	})

	if err := saveSgxQuote(fs, sgxQuote, sgxQuotePath); err != nil {
		return err
	}

	if output != "" {
		if err := pubFile.Write(pubKeyPEM); err != nil {
			return fmt.Errorf("writing public key to file: %w", err)
		}
	} else {
		fmt.Printf("%s\n", pubKeyPEM)
	}
	return nil
}
