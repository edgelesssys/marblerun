package cmd

import (
	"github.com/spf13/cobra"
)

var globalUsage = `The marblerun CLI enables you to install and manage the Marblerun
confidential computing service mesh in your Kubernetes cluster

To install and configure Marblerun, run:

    $ marblerun install
`

var rootCmd = &cobra.Command{
	Use:   "marblerun",
	Short: "Install and manage the Marblerun confidential computing service mesh",
	Long:  globalUsage,
}

// Execute starts the CLI
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(newCertificateCmd())
	rootCmd.AddCommand(newCheckCmd())
	rootCmd.AddCommand(newCompletionCmd())
	rootCmd.AddCommand(newGraphenePrepareCmd())
	rootCmd.AddCommand(newInstallCmd())
	rootCmd.AddCommand(newManifestCmd())
	rootCmd.AddCommand(newNamespaceCmd())
	rootCmd.AddCommand(newPrecheckCmd())
	rootCmd.AddCommand(newRecoverCmd())
	rootCmd.AddCommand(newSecretCmd())
	rootCmd.AddCommand(newSGXSDKPackageInfoCmd())
	rootCmd.AddCommand(newStatusCmd())
	rootCmd.AddCommand(newUninstallCmd())
	rootCmd.AddCommand(newVersionCmd())
}
