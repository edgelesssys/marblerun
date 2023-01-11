// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"fmt"
	"io/ioutil"

	"github.com/spf13/cobra"
)

func newManifestLog() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "log <IP:PORT>",
		Short: "Get the update log from the MarbleRun Coordinator",
		Long: `Get the update log from the MarbleRun Coordinator.
		The log is list of all successful changes to the Coordinator,
		including a timestamp and user performing the operation.`,
		Example: "marblerun manifest log $MARBLERUN",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			cert, err := verifyCoordinator(hostName, eraConfig, insecureEra, acceptedTCBStatuses)
			if err != nil {
				return err
			}
			fmt.Println("Successfully verified Coordinator, now requesting update log")
			response, err := cliDataGet(hostName, "update", "data", cert)
			if err != nil {
				return err
			}
			if len(output) > 0 {
				return ioutil.WriteFile(output, response, 0o644)
			}
			fmt.Printf("Update log:\n%s", string(response))
			return nil
		},
		SilenceUsage: true,
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Save log to file instead of printing to stdout")
	return cmd
}
