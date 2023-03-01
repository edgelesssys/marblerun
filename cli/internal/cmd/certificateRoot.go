// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/spf13/cobra"
)

func newCertificateRoot() *cobra.Command {
	var certFilename string

	cmd := &cobra.Command{
		Use:          "root <IP:PORT>",
		Short:        "Returns the root certificate of the MarbleRun Coordinator",
		Long:         `Returns the root certificate of the MarbleRun Coordinator`,
		Args:         cobra.ExactArgs(1),
		RunE:         runCertificateRoot,
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&certFilename, "output", "o", "marblerunRootCA.crt", "File to save the certificate to")

	return cmd
}

func runCertificateRoot(cmd *cobra.Command, args []string) error {
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
	return cliCertificateRoot(cmd.OutOrStdout(), output, certs)
}

// cliCertificateRoot gets the root certificate of the MarbleRun Coordinator and saves it to a file.
func cliCertificateRoot(out io.Writer, outputFile string, certs []*pem.Block) error {
	if len(certs) == 0 {
		return errors.New("no certificates received from Coordinator")
	}
	if err := os.WriteFile(outputFile, pem.EncodeToMemory(certs[len(certs)-1]), 0o644); err != nil {
		return err
	}
	fmt.Fprintln(out, "Root certificate written to", outputFile)

	return nil
}
