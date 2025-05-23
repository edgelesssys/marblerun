/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"context"
	"os"
	"path/filepath"

	"github.com/edgelesssys/marblerun/api"
	"github.com/edgelesssys/marblerun/cli/internal/cmd"
	"github.com/edgelesssys/marblerun/cli/internal/helm"
	"github.com/spf13/cobra"
)

// defaultCoordinatorCertCache is the default path to the Coordinator's certificate cache.
var defaultCoordinatorCertCache = func() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		panic(err)
	}
	return filepath.Join(configDir, "marblerun", "coordinator-cert.pem")
}()

// Execute starts the CLI.
func Execute() error {
	cobra.EnableCommandSorting = false
	rootCmd := NewRootCmd()
	api.SetLogSink(rootCmd.OutOrStdout())
	return rootCmd.ExecuteContext(context.Background())
}

// NewRootCmd returns the root command of the CLI.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "marblerun",
		Short: "Install and manage the MarbleRun confidential computing service mesh",
		Long: `The marblerun CLI enables you to install and manage the MarbleRun
confidential computing service mesh in your Kubernetes cluster

To install and configure MarbleRun, run:

	$ marblerun install
`,
		PersistentPreRun: preRunRoot,
	}

	// Set output of cmd.Print to stdout. (By default, it's stderr.)
	rootCmd.SetOut(os.Stdout)

	rootCmd.AddCommand(cmd.NewInstallCmd())
	rootCmd.AddCommand(cmd.NewUninstallCmd())
	rootCmd.AddCommand(cmd.NewPrecheckCmd())
	rootCmd.AddCommand(cmd.NewCheckCmd())
	rootCmd.AddCommand(cmd.NewManifestCmd())
	rootCmd.AddCommand(cmd.NewCertificateCmd())
	rootCmd.AddCommand(cmd.NewSecretCmd())
	rootCmd.AddCommand(cmd.NewStatusCmd())
	rootCmd.AddCommand(cmd.NewRecoverCmd())
	rootCmd.AddCommand(cmd.NewPackageInfoCmd())
	rootCmd.AddCommand(cmd.NewVersionCmd())

	rootCmd.PersistentFlags().String("coordinator-cert", defaultCoordinatorCertCache, "Path to MarbleRun Coordinator's root certificate to use for TLS connections")
	rootCmd.PersistentFlags().String("era-config", "", "Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository")
	rootCmd.PersistentFlags().BoolP("insecure", "i", false, "Set to skip quote verification, needed when running in simulation mode")
	rootCmd.PersistentFlags().StringSlice("accepted-tcb-statuses", []string{"UpToDate", "SWHardeningNeeded"}, "Comma-separated list of user accepted TCB statuses")
	rootCmd.PersistentFlags().StringSlice("accepted-advisories", nil, "Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted")
	rootCmd.PersistentFlags().StringP("namespace", "n", helm.Namespace, "Kubernetes namespace of the MarbleRun installation")
	rootCmd.PersistentFlags().String("nonce", "", "(Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)")
	rootCmd.PersistentFlags().String("save-sgx-quote", "", "If set, save the Coordinator's SGX quote to the specified file")

	must(rootCmd.MarkPersistentFlagFilename("coordinator-cert", "pem", "crt"))
	must(rootCmd.MarkPersistentFlagFilename("era-config", "json"))

	return rootCmd
}

func preRunRoot(cmd *cobra.Command, _ []string) {
	cmd.SilenceUsage = true
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
