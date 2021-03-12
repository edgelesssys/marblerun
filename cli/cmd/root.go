package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "marblerun",
	Short: "This CLI allows you to install Marblerun on your cluster and interacts with the control plane through the Client API for all administrative tasks in the service mesh",
	Long:  `This CLI allows you to install Marblerun on your cluster and interacts with the control plane through the Client API for all administrative tasks in the service mesh`,
}

// Execute starts the CLI
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(newCertificateCmd())
	rootCmd.AddCommand(newInstallCmd())
	rootCmd.AddCommand(newManifestCmd())
	rootCmd.AddCommand(newStatusCmd())
	rootCmd.AddCommand(newNamespaceCmd())
	rootCmd.AddCommand(newRecoverCmd())
}
