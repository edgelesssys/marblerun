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

func newNamespaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "namespace",
		Short: "Manages marblerun namespaces",
		Long:  "Manages marblerun namespaces",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newNameSpaceAdd())
	cmd.AddCommand(newNameSpaceGet())

	return cmd
}
