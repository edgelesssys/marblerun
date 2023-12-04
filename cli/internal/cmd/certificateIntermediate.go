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
	"github.com/spf13/cobra"
)

func newCertificateIntermediate() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "intermediate <IP:PORT>",
		Short:   "Returns the intermediate certificate of the MarbleRun Coordinator",
		Long:    `Returns the intermediate certificate of the MarbleRun Coordinator`,
		Args:    cobra.ExactArgs(1),
		RunE:    runCertificate(saveIntermediateCert),
		PreRunE: outputFlagNotEmpty,
	}

	cmd.Flags().StringP("output", "o", "marblerunIntermediateCA.crt", "File to save the certificate to")

	return cmd
}

// cliCertificateIntermediate saves the intermediate certificate of the MarbleRun Coordinator.
func saveIntermediateCert(out io.Writer, certFile *file.Handler, certs []*pem.Block) error {
	if len(certs) < 2 {
		return errors.New("no intermediate certificate received from Coordinator")
	}
	if err := certFile.Write(pem.EncodeToMemory(certs[0]), file.OptOverwrite); err != nil {
		return err
	}
	fmt.Fprintf(out, "Intermediate certificate written to %s\n", certFile.Name())

	return nil
}
