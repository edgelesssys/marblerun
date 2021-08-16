package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func newNameSpaceList() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Lists all namespaces added to a MarbleRun mesh",
		Long:  `Lists all namespaces added to a MarbleRun mesh`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			kubeClient, err := getKubernetesInterface()
			if err != nil {
				return err
			}

			return cliNameSpaceList(kubeClient)
		},
		SilenceUsage: true,
	}
	return cmd
}

// cliNameSpaceList prints out all namespaces added to marblerun
func cliNameSpaceList(kubeClient kubernetes.Interface) error {
	namespaces, err := selectNamespaces(kubeClient)
	if err != nil {
		return err
	}

	if len(namespaces.Items) == 0 {
		fmt.Printf("No namespaces have been added to the MarbleRun mesh\n")
	}

	for _, ns := range namespaces.Items {
		fmt.Printf("%s\n", ns.Name)
	}

	return nil
}

func selectNamespaces(kubeClient kubernetes.Interface) (*v1.NamespaceList, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	selector := fmt.Sprintf("%s=enabled", marblerunAnnotation)

	return kubeClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
}
