package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

func newNameSpaceGet() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Shows all namespaces added to marblerun",
		Long:  `Shows all namespaces added to marblerun`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
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

			return cliNameSpaceGet(clientSet)
		},
		SilenceUsage: true,
	}
	return cmd
}

// cliNameSpaceGet prints out all namespaces added to marblerun
func cliNameSpaceGet(clientSet kubernetes.Interface) error {
	namespaces, err := selectNamespaces(clientSet)
	if err != nil {
		return err
	}

	if len(namespaces.Items) == 0 {
		fmt.Printf("No namespaces have been added to marblerun\n")
	}

	for _, ns := range namespaces.Items {
		fmt.Printf("%s\n", ns.Name)
	}

	return nil
}

func selectNamespaces(clientSet kubernetes.Interface) (*v1.NamespaceList, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	selector := fmt.Sprintf("%s=marblerun", marblerunAnnotation)

	return clientSet.CoreV1().Namespaces().List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
}
