/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"github.com/edgelesssys/marblerun/cli/internal/kube"
	"github.com/spf13/cobra"
)

// Version is the CLI version.
var Version = "0.0.0" // Don't touch! Automatically injected at build-time.

// GitCommit is the git commit hash.
var GitCommit = "0000000000000000000000000000000000000000" // Don't touch! Automatically injected at build-time.

// NewVersionCmd returns the version command.
func NewVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Display version of this CLI and (if running) the MarbleRun Coordinator",
		Long:  `Display version of this CLI and (if running) the MarbleRun Coordinator`,
		Args:  cobra.NoArgs,
		Run:   runVersion,
	}

	return cmd
}

func runVersion(cmd *cobra.Command, _ []string) {
	cmd.Printf("CLI Version: v%s \nCommit: %s\n", Version, GitCommit)
	namespace, err := cmd.Flags().GetString("namespace")
	if err != nil {
		cmd.Println(err)
		return
	}

	cVersion, err := kube.CoordinatorVersion(cmd.Context(), namespace)
	if err != nil {
		cmd.Println("Unable to find MarbleRun Coordinator")
		return
	}
	cmd.Printf("Coordinator Version: %s\n", cVersion)
}
