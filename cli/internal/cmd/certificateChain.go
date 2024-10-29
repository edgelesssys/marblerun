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
func saveCertChain(out io.Writer, certFile *file.Handler, rootCert, intermediateCert *x509.Certificate) error {
	if rootCert == nil || intermediateCert == nil {
		return fmt.Errorf("root and intermediate certificates must not be nil")
	}

	chain := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateCert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})...,
	)

	if err := certFile.Write(chain, file.OptOverwrite); err != nil {
		return err
	}
	fmt.Fprintf(out, "Certificate chain written to %s\n", certFile.Name())

	return nil
}
