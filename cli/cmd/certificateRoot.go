package cmd

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/spf13/cobra"
)

func newCertificateRoot() *cobra.Command {
	var certFilename string

	cmd := &cobra.Command{
		Use:   "root <IP:PORT>",
		Short: "returns the root certificate of the Marblerun coordinator",
		Long:  `returns the root certificate of the Marblerun coordinator`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			return cliCertificateRoot(hostName, certFilename, eraConfig, insecureEra)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&certFilename, "output", "o", "marblerunRootCA.crt", "File to save the certificate to")

	return cmd
}

// cliCertificateRoot gets the root certificate of the Marblerun coordinator and saves it to a file
func cliCertificateRoot(host string, output string, configFilename string, insecure bool) error {
	var certs []*pem.Block
	certs, err := verifyCoordinator(host, configFilename, insecure)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(output, pem.EncodeToMemory(certs[len(certs)-1]), 0644); err != nil {
		return err
	}
	fmt.Println("Root certificate writen to", output)

	return nil
}
