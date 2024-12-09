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
	addClientAuthFlags(cmd, cmd.PersistentFlags())

	cmd.AddCommand(newSecretSet())
	cmd.AddCommand(newSecretGet())

	return cmd
}
