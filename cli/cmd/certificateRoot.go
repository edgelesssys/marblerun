// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"encoding/pem"
	"fmt"
	"io"
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
			return cliCertificateRoot(cmd.OutOrStdout(), hostName, certFilename, eraConfig, insecureEra, acceptedTCBStatuses)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&certFilename, "output", "o", "marblerunRootCA.crt", "File to save the certificate to")

	return cmd
}

// cliCertificateRoot gets the root certificate of the MarbleRun Coordinator and saves it to a file.
func cliCertificateRoot(out io.Writer, host, output, configFilename string, insecure bool, acceptedTCBStatuses []string) error {
	var certs []*pem.Block
	certs, err := verifyCoordinator(out, host, configFilename, insecure, acceptedTCBStatuses)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(output, pem.EncodeToMemory(certs[len(certs)-1]), 0o644); err != nil {
		return err
	}
	fmt.Fprintln(out, "Root certificate written to", output)

	return nil
}
