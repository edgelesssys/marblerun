/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"fmt"

	"github.com/edgelesssys/marblerun/api"
	"github.com/edgelesssys/marblerun/cli/internal/certcache"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

const statusDesc = `
This command provides information about the currently running MarbleRun Coordinator.
Information is obtained from the /status endpoint of the Coordinators REST API.

The Coordinator will be in one of these 4 states:
  0 recovery mode: Found a sealed state of an old seal key. Waiting for user input on /recovery.
	The Coordinator is currently sealed, it can be recovered using the [marblerun recover] command.

  1 uninitialized: Fresh start, initializing the Coordinator.
	The Coordinator is in its starting phase.

  2 waiting for manifest: Waiting for user input on /manifest.
	Send a manifest to the Coordinator using [marblerun manifest set] to start.

  3 accepting marble: The Coordinator is running, you can add marbles to the mesh or update the
    manifest using [marblerun manifest update].
`

// NewStatusCmd returns the status command.
func NewStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status <IP:PORT>",
		Short: "Retrieve information about the status of the MarbleRun Coordinator",
		Long:  statusDesc,
		Args:  cobra.ExactArgs(1),
		RunE:  runStatus,
	}

	return cmd
}

func runStatus(cmd *cobra.Command, args []string) error {
	hostname := args[0]
	root, _, err := certcache.LoadCoordinatorCachedCert(cmd.Flags(), afero.NewOsFs())
	if err != nil {
		return err
	}

	code, msg, err := api.GetStatus(cmd.Context(), hostname, root)
	if err != nil {
		return err
	}
	fmt.Printf("%d: %s\n", code, msg)
	return nil
}
