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
	"os"

	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/spf13/cobra"
)

func newCertificateIntermediate() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "intermediate <IP:PORT>",
		Short: "Returns the intermediate certificate of the MarbleRun Coordinator",
		Long:  `Returns the intermediate certificate of the MarbleRun Coordinator`,
		Args:  cobra.ExactArgs(1),
		RunE:  runCertificateIntermediate,
	}

	cmd.Flags().StringP("output", "o", "marblerunIntermediateCA.crt", "File to save the certificate to")

	return cmd
}

func runCertificateIntermediate(cmd *cobra.Command, args []string) error {
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
	return cliCertificateIntermediate(cmd.OutOrStdout(), output, certs)
}

// cliCertificateIntermediate gets the intermediate certificate of the MarbleRun Coordinator.
func cliCertificateIntermediate(out io.Writer, outputFile string, certs []*pem.Block) error {
	if len(certs) > 1 {
		if err := os.WriteFile(outputFile, pem.EncodeToMemory(certs[0]), 0o644); err != nil {
			return err
		}
		fmt.Fprintln(out, "Intermediate certificate written to", outputFile)
	} else {
		fmt.Fprintln(out, "WARNING: No intermediate certificate received.")
	}

	return nil
}
