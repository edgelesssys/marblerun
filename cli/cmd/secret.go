package cmd

import (
	"github.com/spf13/cobra"
)

var (
	userCertFile string
	userKeyFile  string
)

func newSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manages secrets for the Marblerun coordinator",
		Long: `
Manages secrets for the Marblerun coordinator.
Set or retrieve a secret defined in the manifest.`,
	}

	cmd.PersistentFlags().StringVar(&eraConfig, "era-config", "", "Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github")
	cmd.PersistentFlags().StringVarP(&userCertFile, "cert", "c", "", "PEM encoded Marblerun user certificate file (required)")
	cmd.PersistentFlags().StringVarP(&userKeyFile, "key", "k", "", "PEM encoded Marblerun user key file (required)")
	cmd.PersistentFlags().BoolVarP(&insecureEra, "insecure", "i", false, "Set to skip quote verification, needed when running in simulation mode")
	cmd.MarkPersistentFlagRequired("key")
	cmd.MarkPersistentFlagRequired("cert")
	cmd.AddCommand(newSecretSet())
	cmd.AddCommand(newSecretGet())

	return cmd
}
