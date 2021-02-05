package cmd

import (
	"github.com/spf13/cobra"
)

func newManifestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manifest",
		Short: "Manages manifest for the Marblerun coordinator",
		Long: `
Manages manifests for the Marblerun coordinator.
Used to either set the manifest, update an already set manifest, 
or return a signature of the currently set manifest to the user`,
		Example: "manifest set manifest.json example.com:25555 [--era-config=config.json] [--insecure]",
	}

	cmd.PersistentFlags().StringVar(&eraConfig, "era-config", "", "Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github")
	cmd.PersistentFlags().BoolVarP(&insecureEra, "insecure", "i", false, "Set to skip quote verification, needed when running in simulation mode")
	cmd.AddCommand(newManifestSet())
	cmd.AddCommand(newManifestGet())
	//cmd.AddCommand(newManifestUpdate())

	return cmd
}
