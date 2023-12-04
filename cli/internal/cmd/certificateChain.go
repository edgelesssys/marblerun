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

func newCertificateChain() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "chain <IP:PORT>",
		Short:   "Returns the certificate chain of the MarbleRun Coordinator",
		Long:    `Returns the certificate chain of the MarbleRun Coordinator`,
		Args:    cobra.ExactArgs(1),
		RunE:    runCertificate(saveCertChain),
		PreRunE: outputFlagNotEmpty,
	}

	cmd.Flags().StringP("output", "o", "marblerunChainCA.crt", "File to save the certificate to")

	return cmd
}

// saveCertChain saves the certificate chain of the MarbleRun Coordinator.
func saveCertChain(out io.Writer, certFile *file.Handler, certs []*pem.Block) error {
	if len(certs) == 0 {
		return errors.New("no certificates received from Coordinator")
	}
	if len(certs) == 1 {
		fmt.Fprintln(out, "WARNING: Only received root certificate from Coordinator")
	}

	var chain []byte
	for _, cert := range certs {
		chain = append(chain, pem.EncodeToMemory(cert)...)
	}

	if err := certFile.Write(chain, file.OptOverwrite); err != nil {
		return err
	}
	fmt.Fprintf(out, "Certificate chain written to %s\n", certFile.Name())

	return nil
}
