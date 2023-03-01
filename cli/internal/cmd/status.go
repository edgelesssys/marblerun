// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
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
		Short: "Gives information about the status of the MarbleRun Coordinator",
		Long:  statusDesc,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostname := args[0]
			cert, err := verifyCoordinator(cmd.OutOrStdout(), hostname, eraConfig, insecureEra, acceptedTCBStatuses)
			if err != nil {
				return err
			}
			return cliStatus(hostname, cert)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&eraConfig, "era-config", "", "Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github")
	cmd.Flags().BoolVarP(&insecureEra, "insecure", "i", false, "Set to skip quote verification, needed when running in simulation mode")
	cmd.PersistentFlags().StringSliceVar(&acceptedTCBStatuses, "accepted-tcb-statuses", []string{"UpToDate"}, "Comma-separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded)")

	return cmd
}

// cliStatus requests the current status of the Coordinator.
func cliStatus(host string, cert []*pem.Block) error {
	client, err := restClient(cert, nil)
	if err != nil {
		return err
	}

	resp, err := client.Get("https://" + host + "/status")
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		jsonResponse := gjson.GetBytes(respBody, "data")
		var statusResp statusResponse
		if err := json.Unmarshal([]byte(jsonResponse.String()), &statusResp); err != nil {
			return err
		}
		fmt.Printf("%d: %s\n", statusResp.StatusCode, statusResp.StatusMessage)
	default:
		return fmt.Errorf("error connecting to server: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return nil
}
