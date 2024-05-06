// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"fmt"

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
)

// NewRecoverCmd returns the recover command.
func NewRecoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "recover <recovery_key_decrypted> <IP:PORT>",
		Short:   "Recover the MarbleRun Coordinator from a sealed state",
		Long:    "Recover the MarbleRun Coordinator from a sealed state",
		Example: "marblerun recover recovery_key_decrypted $MARBLERUN",
		Args:    cobra.ExactArgs(2),
		RunE:    runRecover,
	}

	return cmd
}

func runRecover(cmd *cobra.Command, args []string) error {
	keyFile := args[0]
	hostname := args[1]
	fs := afero.NewOsFs()

	recoveryKey, err := file.New(keyFile, fs).Read()
	if err != nil {
		return err
	}

	flags, err := parseRestFlags(cmd.Flags())
	if err != nil {
		return err
	}

	// A Coordinator in recovery mode will have a different certificate than what is cached
	// Only unsealing the Coordinator will allow it to use the original certificate again
	// Therefore we need to verify the Coordinator is running in the expected enclave instead
	caCert, err := rest.VerifyCoordinator(
		cmd.Context(), cmd.OutOrStdout(), hostname,
		flags.eraConfig, flags.k8sNamespace, flags.nonce, flags.insecure, flags.acceptedTCBStatuses,
	)
	if err != nil {
		return err
	}

	client, err := rest.NewClient(hostname, caCert, nil, flags.insecure)
	if err != nil {
		return err
	}
	cmd.Println("Successfully verified Coordinator, now uploading key")
	return cliRecover(cmd, recoveryKey, client)
}

// cliRecover tries to unseal the Coordinator by uploading the recovery key.
func cliRecover(cmd *cobra.Command, key []byte, client poster) error {
	resp, err := client.Post(cmd.Context(), rest.RecoverEndpoint, rest.ContentPlain, bytes.NewReader(key))
	if err != nil {
		return fmt.Errorf("recovering Coordinator: %w", err)
	}

	response := gjson.GetBytes(resp, "StatusMessage")
	cmd.Println(response.String())
	return nil
}
