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

	recoveryKey, err := file.New(keyFile, afero.NewOsFs()).Read()
	if err != nil {
		return err
	}

	client, err := rest.NewClient(cmd, hostname)
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
