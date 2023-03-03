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

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

func newCertificateRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "root <IP:PORT>",
		Short:   "Returns the root certificate of the MarbleRun Coordinator",
		Long:    `Returns the root certificate of the MarbleRun Coordinator`,
		Args:    cobra.ExactArgs(1),
		RunE:    runCertificateRoot,
		PreRunE: outputFlagNotEmpty,
	}

	cmd.Flags().StringP("output", "o", "marblerunRootCA.crt", "File to save the certificate to")

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
	if err != nil {
		return fmt.Errorf("retrieving root certificate from Coordinator: %w", err)
	}
	return cliCertificateRoot(cmd.OutOrStdout(), file.New(output, afero.NewOsFs()), certs)
}

// cliCertificateRoot gets the root certificate of the MarbleRun Coordinator and saves it to a file.
func cliCertificateRoot(out io.Writer, file *file.Handler, certs []*pem.Block) error {
	if len(certs) == 0 {
		return errors.New("no certificates received from Coordinator")
	}
	if err := file.Write(pem.EncodeToMemory(certs[len(certs)-1])); err != nil {
		return err
	}
	fmt.Fprintf(out, "Root certificate written to %s\n", file.Name())

	return nil
}
