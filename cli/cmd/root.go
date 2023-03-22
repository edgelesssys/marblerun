// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"context"
	"os"

	"github.com/edgelesssys/marblerun/cli/internal/cmd"
	"github.com/spf13/cobra"
)

// Execute starts the CLI.
func Execute() error {
	cobra.EnableCommandSorting = false
	rootCmd := NewRootCmd()
	return rootCmd.ExecuteContext(context.Background())
}

// NewRootCmd returns the root command of the CLI.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "marblerun",
		Short: "Install and manage the MarbleRun confidential computing service mesh",
		Long: `The marblerun CLI enables you to install and manage the MarbleRun
confidential computing service mesh in your Kubernetes cluster

To install and configure MarbleRun, run:

	$ marblerun install
`,
		PersistentPreRun: preRunRoot,
	}

	// Set output of cmd.Print to stdout. (By default, it's stderr.)
	rootCmd.SetOut(os.Stdout)

	rootCmd.AddCommand(cmd.NewInstallCmd())
	rootCmd.AddCommand(cmd.NewUninstallCmd())
	rootCmd.AddCommand(cmd.NewPrecheckCmd())
	rootCmd.AddCommand(cmd.NewCheckCmd())
	rootCmd.AddCommand(cmd.NewManifestCmd())
	rootCmd.AddCommand(cmd.NewCertificateCmd())
	rootCmd.AddCommand(cmd.NewSecretCmd())
	rootCmd.AddCommand(cmd.NewStatusCmd())
	rootCmd.AddCommand(cmd.NewRecoverCmd())
	rootCmd.AddCommand(cmd.NewPackageInfoCmd())
	rootCmd.AddCommand(cmd.NewVersionCmd())

	rootCmd.PersistentFlags().String("era-config", "", "Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github")
	rootCmd.PersistentFlags().BoolP("insecure", "i", false, "Set to skip quote verification, needed when running in simulation mode")
	rootCmd.PersistentFlags().StringSlice("accepted-tcb-statuses", []string{"UpToDate"}, "Comma-separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded)")

	must(rootCmd.MarkPersistentFlagFilename("era-config", "json"))

	return rootCmd
}

func preRunRoot(cmd *cobra.Command, args []string) {
	cmd.SilenceUsage = true
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
