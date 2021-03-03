package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

func newNameSpaceAdd() *cobra.Command {
	var dontInjectSgx bool

	cmd := &cobra.Command{
		Use:   "add NAMESPACE ...",
		Short: "Add namespaces to a Marblerun mesh",
		Long:  `Add namespaces to a Marblerun mesh`,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			namespaces := args

			localSettings := envSettings{
				namespace: "marblerun",
			}
			localSettings.config = &genericclioptions.ConfigFlags{
				Namespace: &localSettings.namespace,
			}

			config, err := localSettings.config.ToRESTConfig()
			if err != nil {
				return err
			}

			clientSet, err := kubernetes.NewForConfig(config)
			if err != nil {
				return err
			}

			return cliNameSpaceAdd(namespaces, clientSet, dontInjectSgx)
		},
		SilenceUsage: true,
	}
	cmd.Flags().BoolVar(&dontInjectSgx, "no-sgx-injection", false, "Set to disable automatic injection of SGX tolerations for namespace")

	return cmd
}

// cliNameSpaceAdd adds specified namespaces to the marblerun coordinator
func cliNameSpaceAdd(namespaces []string, clientSet kubernetes.Interface, dontInjectSgx bool) error {
	for _, ns := range namespaces {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var patch string
		if dontInjectSgx {
			patch = fmt.Sprintf(`
{
	"metadata": {
		"labels": {
			"%s": "enabled"
		}
	}
}`, marblerunAnnotation)
		} else {
			patch = fmt.Sprintf(`
{
	"metadata": {
		"labels": {
			"%s": "enabled",
			"%s": "enabled"
		}
	}
}`, marblerunAnnotation, injectionAnnotation)
		}
		// apply patch to namespace
		if _, err := clientSet.CoreV1().Namespaces().Patch(ctx, ns, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{}, ""); err != nil {
			fmt.Printf("Could not apply patch\n")
			return err
		}

		fmt.Printf("Added namespace [%s] to Marblerun mesh\n", ns)
	}
	return nil
}
