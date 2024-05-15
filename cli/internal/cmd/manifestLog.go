// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/edgelesssys/marblerun/api"
	"github.com/edgelesssys/marblerun/cli/internal/certcache"
	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
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
	fs := afero.NewOsFs()

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}

	root, _, err := certcache.LoadCoordinatorCachedCert(cmd.Flags(), fs)
	if err != nil {
		return err
	}

	getManifestLog := func(ctx context.Context) ([]string, error) {
		return api.ManifestLog(ctx, hostname, root)
	}

	cmd.Println("Successfully verified Coordinator, now requesting update log")
	return cliManifestLog(cmd, file.New(output, fs), getManifestLog)
}

func cliManifestLog(
	cmd *cobra.Command, logFile *file.Handler,
	getManifetLog func(context.Context) ([]string, error),
) error {
	log, err := getManifetLog(cmd.Context())
	if err != nil {
		return fmt.Errorf("retrieving update log: %w", err)
	}

	logStr := strings.Join(log, "\n")

	if logFile != nil {
		return logFile.Write([]byte(logStr), file.OptOverwrite)
	}
	cmd.Printf("Update log:\n%s\n", logStr)
	return nil
}
