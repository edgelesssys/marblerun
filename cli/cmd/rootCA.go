package cmd

import (
	"fmt"
	"io/ioutil"

	"github.com/spf13/cobra"
)

var rootCAFilename string

func newRootCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rootca <IP:PORT>",
		Short: "returns the rootCA of the marblerun coordinator",
		Long:  `returns the rootCA of the marblerun coordinator`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			return CliRootCA(hostName, rootCAFilename, eraConfig, insecureEra)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&rootCAFilename, "output", "o", "marblerun.crt", "File to save the certificate to")
	cmd.Flags().StringVar(&eraConfig, "era-config", "", eraString)
	cmd.Flags().BoolVarP(&insecureEra, "insecure", "i", false, "Set to skip quote verification, needed when running in simulation mode")
	return cmd
}

// CliRootCA gets the rootCA of the marblerun coordinator and saves it to
func CliRootCA(host string, output string, configFilename string, insecure bool) error {
	cert, err := VerifyCoordinator(host, configFilename, insecure)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(output, []byte(cert), 0644); err != nil {
		return err
	}
	fmt.Printf("Certificate written to: %s\n", output)

	return nil
}
