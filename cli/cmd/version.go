package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var Version = "0.3.0-dev"
var BuildDate string

func newVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Display version of this CLI and (if running) the Marblerun coordinator",
		Long:  `Display version of this CLI and (if running) the Marblerun coordinator`,
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("CLI Version: v%s \nBuild Date: %s\n", Version, BuildDate)

			cVersion, err := getCoordinatorVersion()
			if err != nil {
				fmt.Println("Unable to find Marblerun coordinator")
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

	coordinatorDeployment, err := kubeClient.AppsV1().Deployments("marblerun").Get(context.TODO(), "marblerun-coordinator", metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	version := coordinatorDeployment.Labels["app.kubernetes.io/version"]
	if len(version) <= 0 {
		return "", fmt.Errorf("deployment has no label [app.kubernetes.io/version]")
	}
	return version, nil
}
