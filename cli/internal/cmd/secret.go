// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"github.com/spf13/cobra"
)

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
