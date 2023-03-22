// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

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

func outputFlagNotEmpty(cmd *cobra.Command, args []string) error {
	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	if output == "" {
		return errors.New("output flag must not be empty")
	}
	return nil
}
