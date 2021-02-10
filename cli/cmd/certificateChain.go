package cmd

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/spf13/cobra"
)

func newCertificateChain() *cobra.Command {
	var certFilename string

	cmd := &cobra.Command{
		Use:   "chain <IP:PORT>",
		Short: "returns the certificate chain of the Marblerun coordinator",
		Long:  `returns the certificate chain of the Marblerun coordinator`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			return cliCertificateChain(hostName, certFilename, eraConfig, insecureEra)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&certFilename, "output", "o", "marblerunChainCA.crt", "File to save the certificate to")

	return cmd
}

// cliCertificateChain gets the certificate chain of the Marblerun coordinator
func cliCertificateChain(host string, output string, configFilename string, insecure bool) error {
	certs, err := verifyCoordinator(host, configFilename, insecure)
	if err != nil {
		return err
	}

	if len(certs) == 1 {
		fmt.Println("WARNING: Only received root certificate from host.")
	}

	var chain []byte
	for _, cert := range certs {
		chain = append(chain, pem.EncodeToMemory(cert)...)
	}

	if err := ioutil.WriteFile(output, chain, 0644); err != nil {
		return err
	}

	fmt.Println("Certificate chain writen to", output)

	return nil
}
