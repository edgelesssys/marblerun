// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/edgelesssys/marblerun/cli/internal/rest"
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

type statusResponse struct {
	StatusCode    int    `json:"StatusCode"`
	StatusMessage string `json:"StatusMessage"`
}

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
	client, err := rest.NewClient(cmd, hostname)
	if err != nil {
		return err
	}
	return cliStatus(cmd, client)
}

// cliStatus requests the current status of the Coordinator.
func cliStatus(cmd *cobra.Command, client getter) error {
	resp, err := client.Get(cmd.Context(), rest.StatusEndpoint, http.NoBody)
	if err != nil {
		return fmt.Errorf("querying Coordinator status: %w", err)
	}

	var statusResp statusResponse
	if err := json.Unmarshal(resp, &statusResp); err != nil {
		return err
	}
	cmd.Printf("%d: %s\n", statusResp.StatusCode, statusResp.StatusMessage)

	return nil
}
