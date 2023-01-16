// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
)

func newRecoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "recover <recovery_key_decrypted> <IP:PORT>",
		Short:   "Recovers the MarbleRun Coordinator from a sealed state",
		Long:    "Recovers the MarbleRun Coordinator from a sealed state",
		Example: "marblerun recover recovery_key_decrypted $MARBLERUN",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyFile := args[0]
			hostName := args[1]

			cert, err := verifyCoordinator(hostName, eraConfig, insecureEra, acceptedTCBStatuses)
			if err != nil {
				return err
			}

			// read in key
			recoveryKey, err := ioutil.ReadFile(keyFile)
			if err != nil {
				return err
			}

			fmt.Println("Successfully verified Coordinator, now uploading key")

			return cliRecover(hostName, recoveryKey, cert)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&eraConfig, "era-config", "", "Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github")
	cmd.Flags().BoolVarP(&insecureEra, "insecure", "i", false, "Set to skip quote verification, needed when running in simulation mode")
	cmd.PersistentFlags().StringSliceVar(&acceptedTCBStatuses, "accepted-tcb-statuses", []string{"UpToDate"}, "Comma-separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded)")

	return cmd
}

// cliRecover tries to unseal the Coordinator by uploading the recovery key.
func cliRecover(host string, key []byte, cert []*pem.Block) error {
	client, err := restClient(cert, nil)
	if err != nil {
		return err
	}

	url := url.URL{Scheme: "https", Host: host, Path: "recover"}
	resp, err := client.Post(url.String(), "text/plain", bytes.NewReader(key))
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		jsonResponse := gjson.GetBytes(respBody, "data.StatusMessage")
		fmt.Printf("%s \n", jsonResponse.String())
	default:
		return fmt.Errorf("error connecting to server: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return nil
}
