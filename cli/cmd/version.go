package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Version is the CLI version.
var Version = "0.0.0" // Don't touch! Automatically injected at build-time.

// GitCommit is the git commit hash.
var GitCommit = "0000000000000000000000000000000000000000" // Don't touch! Automatically injected at build-time.

func newVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Display version of this CLI and (if running) the MarbleRun Coordinator",
		Long:  `Display version of this CLI and (if running) the MarbleRun Coordinator`,
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("CLI Version: v%s \nCommit: %s\n", Version, GitCommit)

			cVersion, err := getCoordinatorVersion()
			if err != nil {
				fmt.Println("Unable to find MarbleRun Coordinator")
				return
			}
			fmt.Printf("Coordinator Version: %s\n", cVersion)
		},
		SilenceUsage: true,
	}

	return cmd
}

func getCoordinatorVersion() (string, error) {
	kubeClient, err := getKubernetesInterface()
	if err != nil {
		return "", err
	}

	coordinatorDeployment, err := kubeClient.AppsV1().Deployments(helmNamespace).Get(context.TODO(), helmCoordinatorDeployment, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	version := coordinatorDeployment.Labels["app.kubernetes.io/version"]
	if len(version) <= 0 {
		return "", fmt.Errorf("deployment has no label [app.kubernetes.io/version]")
	}
	return version, nil
}
