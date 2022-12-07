// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"github.com/spf13/cobra"
)

var globalUsage = `The marblerun CLI enables you to install and manage the MarbleRun
confidential computing service mesh in your Kubernetes cluster

To install and configure MarbleRun, run:

    $ marblerun install
`

var rootCmd = &cobra.Command{
	Use:   "marblerun",
	Short: "Install and manage the MarbleRun confidential computing service mesh",
	Long:  globalUsage,
}

// Execute starts the CLI.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(newCertificateCmd())
	rootCmd.AddCommand(newCheckCmd())
	rootCmd.AddCommand(newCompletionCmd())
	rootCmd.AddCommand(newGraminePrepareCmd())
	rootCmd.AddCommand(newInstallCmd())
	rootCmd.AddCommand(newManifestCmd())
	rootCmd.AddCommand(newPrecheckCmd())
	rootCmd.AddCommand(newRecoverCmd())
	rootCmd.AddCommand(newSecretCmd())
	rootCmd.AddCommand(newPackageInfoCmd())
	rootCmd.AddCommand(newStatusCmd())
	rootCmd.AddCommand(newUninstallCmd())
	rootCmd.AddCommand(newVersionCmd())
}
