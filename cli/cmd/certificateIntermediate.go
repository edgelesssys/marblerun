package cmd

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/spf13/cobra"
)

func newCertificateIntermediate() *cobra.Command {
	var certFilename string

	cmd := &cobra.Command{
		Use:   "intermediate <IP:PORT>",
		Short: "returns the intermediateCA of the marblerun coordinator",
		Long:  `returns the intermediateCA of the marblerun coordinator`,
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

// cliCertificateIntermediate gets the intermediateCA of the Marblerun coordinator
func cliCertificateIntermediate(host string, output string, configFilename string, insecure bool) error {
	cert, err := verifyCoordinator(host, configFilename, insecure)
	if err != nil {
		return err
	}

	// Seperate rootCA from intermediateCA, if only one certificate save nothing and notify the user
	var intermediateCA string
	certSplit := strings.SplitAfter(cert, "-----END CERTIFICATE-----\n")
	if len(certSplit) == 3 {
		intermediateCA = certSplit[0]
		if err := ioutil.WriteFile(output, []byte(intermediateCA), 0644); err != nil {
			return err
		}
		fmt.Printf("Certificate written to: %s\n", output)
		return nil
	}

	fmt.Println("Got no intermediate certificate from the Marblerun coordinator")

	return nil
}
