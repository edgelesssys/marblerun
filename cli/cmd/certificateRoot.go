package cmd

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/spf13/cobra"
)

func newCertificateRoot() *cobra.Command {
	var rootCAFilename string

	cmd := &cobra.Command{
		Use:   "root <IP:PORT>",
		Short: "returns the rootCA of the marblerun coordinator",
		Long:  `returns the rootCA of the marblerun coordinator`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			return cliCertificateRoot(hostName, rootCAFilename, eraConfig, insecureEra)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&rootCAFilename, "output", "o", "marblerunRootCA.crt", "File to save the certificate to")

	return cmd
}

// cliCertificateRoot gets the rootCA of the Marblerun coordinator and saves it to a file
func cliCertificateRoot(host string, output string, configFilename string, insecure bool) error {
	cert, err := verifyCoordinator(host, configFilename, insecure)
	if err != nil {
		return err
	}

	// Seperate rootCA from intermediateCA, if only one certificate was returned save it as rootCA
	var rootCA string
	certSplit := strings.SplitAfter(cert, "-----END CERTIFICATE-----\n")
	if len(certSplit) == 3 {
		rootCA = certSplit[1]
	} else {
		rootCA = certSplit[0]
	}

	if err := ioutil.WriteFile(output, []byte(rootCA), 0644); err != nil {
		return err
	}
	fmt.Printf("Certificate written to: %s\n", output)

	return nil
}
