// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"fmt"
	"net/http"
	"os"

	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
)

func newManifestLog() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "log <IP:PORT>",
		Short: "Get the update log from the MarbleRun Coordinator",
		Long: `Get the update log from the MarbleRun Coordinator.
		The log is list of all successful changes to the Coordinator,
		including a timestamp and user performing the operation.`,
		Example: "marblerun manifest log $MARBLERUN",
		Args:    cobra.ExactArgs(1),
		RunE:    runManifestLog,
	}
	cmd.Flags().StringP("output", "o", "", "Save log to file instead of printing to stdout")
	return cmd
}

func runManifestLog(cmd *cobra.Command, args []string) error {
	hostname := args[0]

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	client, err := rest.NewClient(cmd, hostname)
	if err != nil {
		return err
	}

	cmd.Println("Successfully verified Coordinator, now requesting update log")
	return cliManifestLog(cmd, output, client)
}

func cliManifestLog(cmd *cobra.Command, outputFile string, client getter) error {
	resp, err := client.Get(cmd.Context(), "update", http.NoBody)
	if err != nil {
		return fmt.Errorf("unable to retrieve update log: %w", err)
	}

	log := gjson.GetBytes(resp, "data").String()

	if outputFile != "" {
		return os.WriteFile(outputFile, []byte(log), 0o644)
	}
	cmd.Printf("Update log:\n%s", log)
	return nil
}
