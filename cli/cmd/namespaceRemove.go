package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

func newNameSpaceRemove() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove NAMESPACE",
		Short: "Remove namespaces from a Marblerun mesh",
		Long:  `Remove namespaces from a Marblerun mesh`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			namespace := args[0]

			kubeClient, err := getKubernetesInterface()
			if err != nil {
				return err
			}

			return cliNameSpaceRemove(namespace, kubeClient)
		},
		SilenceUsage: true,
	}
	return cmd
}

func cliNameSpaceRemove(namespace string, kubeClient kubernetes.Interface) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	k8sNamespace, err := kubeClient.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return err
	}

	val, exists := k8sNamespace.ObjectMeta.Labels[marblerunAnnotation]
	if exists {
		if val == "enabled" {
			patch := fmt.Sprintf(`
{
	"metadata": {
		"labels": {
			"%s": null,
			"%s": null
		}
	}
}
`, marblerunAnnotation, injectionAnnotation)
			if _, err := kubeClient.CoreV1().Namespaces().Patch(ctx, namespace, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{}, ""); err != nil {
				return err
			}

			fmt.Printf("Namespace [%s] succesfully removed from the Marblerun mesh\n", namespace)
		} else {
			return fmt.Errorf("unexpected value in namespace label: %s", val)
		}
	} else {
		return fmt.Errorf("Namespace [%s] does not belong to the Marblerun mesh", namespace)
	}

	return nil
}
