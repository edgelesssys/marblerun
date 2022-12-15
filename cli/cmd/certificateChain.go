// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
		Short: "Returns the certificate chain of the MarbleRun Coordinator",
		Long:  `Returns the certificate chain of the MarbleRun Coordinator`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			return cliCertificateChain(hostName, certFilename, eraConfig, insecureEra, acceptedTCBStatuses)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&certFilename, "output", "o", "marblerunChainCA.crt", "File to save the certificate to")

	return cmd
}

// cliCertificateChain gets the certificate chain of the MarbleRun Coordinator.
func cliCertificateChain(host string, output string, configFilename string, insecure bool, acceptedTCBStatuses []string) error {
	certs, err := verifyCoordinator(host, configFilename, insecure, acceptedTCBStatuses)
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

	if err := ioutil.WriteFile(output, chain, 0o644); err != nil {
		return err
	}

	fmt.Println("Certificate chain written to", output)

	return nil
}
