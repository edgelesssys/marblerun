/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"github.com/spf13/cobra"
)

// NewSecretCmd returns the secret command.
func NewSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage secrets for the MarbleRun Coordinator",
		Long: `
Manage secrets for the MarbleRun Coordinator.
Set or retrieve a secret defined in the manifest.`,
	}

	cmd.PersistentFlags().StringP("cert", "c", "", "PEM encoded MarbleRun user certificate file (required)")
	cmd.PersistentFlags().StringP("key", "k", "", "PEM encoded MarbleRun user key file (required)")
	must(cmd.MarkPersistentFlagRequired("key"))
	must(cmd.MarkPersistentFlagRequired("cert"))

	cmd.AddCommand(newSecretSet())
	cmd.AddCommand(newSecretGet())

	return cmd
}
