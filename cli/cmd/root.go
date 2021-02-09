package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "marblerun",
	Short: "marblerun cli short description",
	Long:  `marblerun cli long description`,
}

// Execute starts the CLI
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(newRootCACmd())
	rootCmd.AddCommand(newInstallCmd())
	rootCmd.AddCommand(newManifestCmd())
	rootCmd.AddCommand(newStatusCmd())
	rootCmd.AddCommand(newNamespaceCmd())
	rootCmd.AddCommand(newRecoverCmd())
}
