package cmd

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/spf13/cobra"
)

func newCertificateIntermediate() *cobra.Command {
	var certFilename string

	cmd := &cobra.Command{
		Use:   "intermediate <IP:PORT>",
		Short: "Returns the intermediate certificate of the Marblerun coordinator",
		Long:  `Returns the intermediate certificate of the Marblerun coordinator`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			return cliCertificateIntermediate(hostName, certFilename, eraConfig, insecureEra)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&certFilename, "output", "o", "marblerunIntermediateCA.crt", "File to save the certificate to")

	return cmd
}

// cliCertificateIntermediate gets the intermediate certificate of the Marblerun coordinator
func cliCertificateIntermediate(host string, output string, configFilename string, insecure bool) error {
	certs, err := verifyCoordinator(host, configFilename, insecure)
	if err != nil {
		return err
	}

	if len(certs) > 1 {
		if err := ioutil.WriteFile(output, pem.EncodeToMemory(certs[0]), 0644); err != nil {
			return err
		}
		fmt.Println("Intermediate certificate writen to", output)
	} else {
		fmt.Println("WARNING: No intermediate certificate received.")
	}

	return nil
}
