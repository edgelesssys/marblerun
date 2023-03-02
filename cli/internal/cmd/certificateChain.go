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

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/spf13/cobra"
)

func newCertificateChain() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "chain <IP:PORT>",
		Short:   "Returns the certificate chain of the MarbleRun Coordinator",
		Long:    `Returns the certificate chain of the MarbleRun Coordinator`,
		Args:    cobra.ExactArgs(1),
		RunE:    runCertificateChain,
		PreRunE: outputFlagNotEmpty,
	}

	cmd.Flags().StringP("output", "o", "marblerunChainCA.crt", "File to save the certificate to")

	return cmd
}

func runCertificateChain(cmd *cobra.Command, args []string) error {
	hostname := args[0]
	flags, err := rest.ParseFlags(cmd)
	if err != nil {
		return err
	}
	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	certs, err := rest.VerifyCoordinator(
		cmd.Context(), cmd.OutOrStdout(), hostname,
		flags.EraConfig, flags.Insecure, flags.AcceptedTCBStatuses,
	)
	return cliCertificateChain(cmd.OutOrStdout(), file.New(output), certs)
}

// cliCertificateChain gets the certificate chain of the MarbleRun Coordinator.
func cliCertificateChain(out io.Writer, file fileWriter, certs []*pem.Block) error {
	if len(certs) == 1 {
		fmt.Fprintln(out, "WARNING: Only received root certificate from host.")
	}

	var chain []byte
	for _, cert := range certs {
		chain = append(chain, pem.EncodeToMemory(cert)...)
	}

	if err := file.Write(chain); err != nil {
		return err
	}
	fmt.Fprintf(out, "Certificate chain written to %s\n", file.Name())

	return nil
}
