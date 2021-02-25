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
	var injectSgx bool

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

			return cliNameSpaceAdd(namespaces, clientSet, injectSgx)
		},
		SilenceUsage: true,
	}
	cmd.Flags().BoolVar(&injectSgx, "inject-sgx", false, "Set to enable automatic injection of SGX tolerations for namespace")

	return cmd
}

// cliNameSpaceAdd adds specified namespaces to the marblerun coordinator
func cliNameSpaceAdd(namespaces []string, clientSet kubernetes.Interface, injectSgx bool) error {
	for _, ns := range namespaces {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var patch string
		if injectSgx {
			patch = fmt.Sprintf(`
{
	"metadata": {
		"labels": {
			"%s": "enabled",
			"%s": "enabled"
		}
	}
}`, marblerunAnnotation, injectionAnnotation)
		} else {
			patch = fmt.Sprintf(`
{
	"metadata": {
		"labels": {
			"%s": "marblerun"
		}
	}
}`, marblerunAnnotation)
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
