// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/spf13/cobra"
)

func newCertificateRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "root <IP:PORT>",
		Short:   "Returns the root certificate of the MarbleRun Coordinator",
		Long:    `Returns the root certificate of the MarbleRun Coordinator`,
		Args:    cobra.ExactArgs(1),
		RunE:    runCertificate(saveRootCert),
		PreRunE: outputFlagNotEmpty,
	}

	cmd.Flags().StringP("output", "o", "marblerunRootCA.crt", "File to save the certificate to")

	return cmd
}

// saveRootCert saves the root certificate of the MarbleRun Coordinator to a file.
func saveRootCert(out io.Writer, certFile *file.Handler, root, _ *x509.Certificate) error {
	if root == nil {
		return fmt.Errorf("root certificate must not be nil")
	}

	if err := certFile.Write(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: root.Raw,
	}), file.OptOverwrite); err != nil {
		return err
	}
	fmt.Fprintf(out, "Root certificate written to %s\n", certFile.Name())

	return nil
}
