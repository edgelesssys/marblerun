package cmd

import (
	"fmt"
	"io/ioutil"

	"github.com/spf13/cobra"
)

func newManifestGet() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "get <IP:PORT>",
		Short: "Get the manifest signature from the Marblerun coordinator",
		Long:  `Get the manifest signature from the Marblerun coordinator`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			cert, err := verifyCoordinator(hostName, eraConfig, insecureEra)
			if err != nil {
				return err
			}
			fmt.Println("Successfully verified coordinator, now requesting manifest signature")
			response, err := cliDataGet(hostName, "manifest", "data.ManifestSignature", cert)
			if err != nil {
				return err
			}
			if len(output) > 0 {
				return ioutil.WriteFile(output, response, 0644)
			}
			fmt.Printf("Manifest signature: %s\n", string(response))
			return nil
		},
		SilenceUsage: true,
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Save singature to file instead of printing to stdout")
	return cmd
}
