package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/spf13/cobra"
)

const statusDesc = `
This command provides information about the currently running Marblerun coordinator.
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
	Code   int    `json:"Code"`
	Status string `json:"Status"`
}

func newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status <IP:PORT>",
		Short: "Gives information about the status of the marblerun Coordinator",
		Long:  statusDesc,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostname := args[0]
			return cliStatus(hostname, eraConfig, insecureEra)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&eraConfig, "era-config", "", "Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github")
	cmd.Flags().BoolVarP(&insecureEra, "insecure", "i", false, "Set to skip quote verification, needed when running in simulation mode")

	return cmd
}

// cliStatus requests the current status of the coordinator
func cliStatus(host string, configFilename string, insecure bool) error {
	cert, err := verifyCoordinator(host, configFilename, insecure)
	if err != nil {
		return err
	}

	client, err := restClient(cert)
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
		var statusResp statusResponse
		if err := json.Unmarshal(respBody, &statusResp); err != nil {
			return err
		}
		fmt.Printf("%d: %s\n", statusResp.Code, statusResp.Status)
	default:
		return fmt.Errorf("error connecting to server: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return nil
}
