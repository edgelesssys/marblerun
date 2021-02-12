package cmd

import (
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

type envSettings struct {
	namespace string
	config    *genericclioptions.ConfigFlags
}

// injected monitor annotation
const marblerunAnnotation = "marblerun/monitor"
const injectionAnnotation = "marblerun/injectsgx"

func newNamespaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "namespace",
		Short: "Manages namespaces associated with Marblerun installations",
		Long:  "Manages namespaces associated with Marblerun installations",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newNameSpaceAdd())
	cmd.AddCommand(newNameSpaceList())
	cmd.AddCommand(newNameSpaceRemove())

	return cmd
}
