/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"crypto/x509"
	"encoding/pem"
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
func saveIntermediateCert(out io.Writer, certFile *file.Handler, _, intermediate *x509.Certificate) error {
	if intermediate == nil {
		return fmt.Errorf("intermediate certificate must not be nil")
	}

	if err := certFile.Write(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: intermediate.Raw,
	}), file.OptOverwrite); err != nil {
		return err
	}
	fmt.Fprintf(out, "Intermediate certificate written to %s\n", certFile.Name())

	return nil
}
