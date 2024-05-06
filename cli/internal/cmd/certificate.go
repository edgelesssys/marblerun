// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

// NewCertificateCmd returns the certificate command.
func NewCertificateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certificate",
		Short: "Retrieves the certificate of the MarbleRun Coordinator",
		Long:  `Retrieves the certificate of the MarbleRun Coordinator`,
	}

	cmd.AddCommand(newCertificateRoot())
	cmd.AddCommand(newCertificateIntermediate())
	cmd.AddCommand(newCertificateChain())

	return cmd
}

func runCertificate(saveCert func(io.Writer, *file.Handler, []*pem.Block) error,
) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		hostname := args[0]
		fs := afero.NewOsFs()
		verifyOpts, err := parseRestFlags(cmd.Flags())
		if err != nil {
			return err
		}
		output, err := cmd.Flags().GetString("output")
		if err != nil {
			return err
		}

		localCerts, err := rest.LoadCoordinatorCachedCert(cmd.Flags(), fs)
		if err != nil {
			return err
		}
		rootCert, err := getRootCertFromPEMChain(localCerts)
		if err != nil {
			return fmt.Errorf("parsing root certificate from local cache: %w", err)
		}

		certs, err := rest.VerifyCoordinator(cmd.Context(), cmd.OutOrStdout(), hostname, verifyOpts)
		if err != nil {
			return fmt.Errorf("retrieving certificate from Coordinator: %w", err)
		}

		remoteRootCert, err := getRootCertFromPEMChain(certs)
		if err != nil {
			return fmt.Errorf("parsing root certificate from Coordinator: %w", err)
		}

		if !remoteRootCert.Equal(rootCert) {
			return errors.New("root certificate of Coordinator changed. Run 'marblerun manifest verify' to verify the instance and update the local cache")
		}

		return saveCert(cmd.OutOrStdout(), file.New(output, fs), certs)
	}
}

func outputFlagNotEmpty(cmd *cobra.Command, _ []string) error {
	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	if output == "" {
		return errors.New("output flag must not be empty")
	}
	return nil
}

func getRootCertFromPEMChain(certs []*pem.Block) (*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, errors.New("no certificates received from Coordinator")
	}
	return x509.ParseCertificate(certs[len(certs)-1].Bytes)
}
