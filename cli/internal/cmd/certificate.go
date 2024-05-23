// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/edgelesssys/marblerun/api"
	"github.com/edgelesssys/marblerun/cli/internal/certcache"
	"github.com/edgelesssys/marblerun/cli/internal/file"
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

func runCertificate(saveCert func(writer io.Writer, fh *file.Handler, root, intermediate *x509.Certificate) error,
) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		hostname := args[0]
		fs := afero.NewOsFs()
		verifyOpts, sgxQuotePath, err := parseRestFlags(cmd)
		if err != nil {
			return err
		}
		output, err := cmd.Flags().GetString("output")
		if err != nil {
			return err
		}

		remoteRootCert, remoteIntermediateCert, sgxQuote, err := api.VerifyCoordinator(cmd.Context(), hostname, verifyOpts)
		if err != nil {
			return fmt.Errorf("retrieving certificate from Coordinator: %w", err)
		}

		rootCert, _, err := certcache.LoadCoordinatorCachedCert(cmd.Flags(), fs)
		if err != nil {
			return err
		}

		if !remoteRootCert.Equal(rootCert) {
			return errors.New("root certificate of Coordinator changed. Run 'marblerun manifest verify' to verify the instance and update the local cache")
		}

		if err := saveSgxQuote(fs, sgxQuote, sgxQuotePath); err != nil {
			return err
		}
		return saveCert(cmd.OutOrStdout(), file.New(output, fs), remoteRootCert, remoteIntermediateCert)
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
