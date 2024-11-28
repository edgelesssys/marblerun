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

	cmd.PersistentFlags().StringP("cert", "c", "", "PEM encoded MarbleRun user certificate file")
	cmd.PersistentFlags().StringP("key", "k", "", "PEM encoded MarbleRun user key file")
	cmd.MarkFlagsRequiredTogether("key", "cert")

	cmd.PersistentFlags().String("pkcs11-config", "", "Path to a PKCS#11 configuration file to load the client certificate with")
	cmd.PersistentFlags().String("pkcs11-key-id", "", "ID of the private key in the PKCS#11 token")
	cmd.PersistentFlags().String("pkcs11-key-label", "", "Label of the private key in the PKCS#11 token")
	cmd.PersistentFlags().String("pkcs11-cert-id", "", "ID of the certificate in the PKCS#11 token")
	cmd.PersistentFlags().String("pkcs11-cert-label", "", "Label of the certificate in the PKCS#11 token")
	must(cmd.MarkPersistentFlagFilename("pkcs11-config", "json"))
	cmd.MarkFlagsOneRequired("pkcs11-key-id", "pkcs11-key-label", "cert")
	cmd.MarkFlagsOneRequired("pkcs11-cert-id", "pkcs11-cert-label", "cert")

	cmd.MarkFlagsMutuallyExclusive("pkcs11-config", "cert")
	cmd.MarkFlagsMutuallyExclusive("pkcs11-config", "key")
	cmd.MarkFlagsOneRequired("pkcs11-config", "cert")
	cmd.MarkFlagsOneRequired("pkcs11-config", "key")

	cmd.AddCommand(newSecretSet())
	cmd.AddCommand(newSecretGet())

	return cmd
}
