package cmd

import (
	"github.com/spf13/cobra"
)

func newCertificateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certificate",
		Short: "Retrieves the certificate of the Marblerun coordinator",
		Long:  `Retrieves the certificate of the Marblerun coordinator`,
	}

	cmd.PersistentFlags().StringVar(&eraConfig, "era-config", "", "Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github")
	cmd.PersistentFlags().BoolVarP(&insecureEra, "insecure", "i", false, "Set to skip quote verification, needed when running in simulation mode")
	cmd.AddCommand(newCertificateRoot())
	cmd.AddCommand(newCertificateIntermediate())

	return cmd
}
