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
		Short: "Returns the root certificate of the MarbleRun Coordinator",
		Long:  `Returns the root certificate of the MarbleRun Coordinator`,
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

// cliCertificateRoot gets the root certificate of the MarbleRun Coordinator and saves it to a file.
func cliCertificateRoot(host string, output string, configFilename string, insecure bool) error {
	var certs []*pem.Block
	certs, err := verifyCoordinator(host, configFilename, insecure)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(output, pem.EncodeToMemory(certs[len(certs)-1]), 0o644); err != nil {
		return err
	}
	fmt.Println("Root certificate written to", output)

	return nil
}
