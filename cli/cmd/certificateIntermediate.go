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

func newCertificateIntermediate() *cobra.Command {
	var certFilename string

	cmd := &cobra.Command{
		Use:   "intermediate <IP:PORT>",
		Short: "Returns the intermediate certificate of the MarbleRun Coordinator",
		Long:  `Returns the intermediate certificate of the MarbleRun Coordinator`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			return cliCertificateIntermediate(cmd.OutOrStdout(), hostName, certFilename, eraConfig, insecureEra, acceptedTCBStatuses)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&certFilename, "output", "o", "marblerunIntermediateCA.crt", "File to save the certificate to")

	return cmd
}

// cliCertificateIntermediate gets the intermediate certificate of the MarbleRun Coordinator.
func cliCertificateIntermediate(out io.Writer, host, output, configFilename string, insecure bool, acceptedTCBStatuses []string) error {
	certs, err := verifyCoordinator(out, host, configFilename, insecure, acceptedTCBStatuses)
	if err != nil {
		return err
	}

	if len(certs) > 1 {
		if err := ioutil.WriteFile(output, pem.EncodeToMemory(certs[0]), 0o644); err != nil {
			return err
		}
		fmt.Fprintln(out, "Intermediate certificate written to", output)
	} else {
		fmt.Fprintln(out, "WARNING: No intermediate certificate received.")
	}

	return nil
}
