package cmd

import (
	"github.com/spf13/cobra"
)

// injected monitor annotation
const marblerunAnnotation = "marblerun/inject"
const injectionAnnotation = "marblerun/inject-sgx"

func newNamespaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "namespace",
		Short: "Manages namespaces associated with MarbleRun installations",
		Long:  "Manages namespaces associated with MarbleRun installations",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newNameSpaceAdd())
	cmd.AddCommand(newNameSpaceList())
	cmd.AddCommand(newNameSpaceRemove())

	return cmd
}
