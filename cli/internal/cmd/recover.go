// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"github.com/edgelesssys/marblerun/api"
	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

// NewRecoverCmd returns the recover command.
func NewRecoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "recover <recovery_key_decrypted> <IP:PORT>",
		Short:   "Recover the MarbleRun Coordinator from a sealed state",
		Long:    "Recover the MarbleRun Coordinator from a sealed state",
		Example: "marblerun recover recovery_key_decrypted $MARBLERUN",
		Args:    cobra.ExactArgs(2),
		RunE:    runRecover,
	}

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

	remaining, sgxQuote, err := api.Recover(cmd.Context(), hostname, verifyOpts, recoveryKey)
	if err != nil {
		return err
	}

	if remaining == 0 {
		cmd.Println("Recovery successful.")
	} else {
		cmd.Printf("Secret was processed successfully. Upload the next secret. Remaining secrets: %d", remaining)
	}

	if err := saveSgxQuote(fs, sgxQuote, sgxQuotePath); err != nil {
		return err
	}
	return nil
}
