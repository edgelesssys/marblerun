/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// Package cmd implements the MarbleRun's CLI commands.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/edgelesssys/marblerun/api"
	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/cli/internal/kube"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const eraDefaultConfig = "era-config.json"

func webhookDNSName(namespace string) string {
	return "marble-injector." + namespace
}

func addClientAuthFlags(cmd *cobra.Command, flags *pflag.FlagSet) {
	flags.StringP("cert", "c", "", "PEM encoded admin certificate file")
	flags.StringP("key", "k", "", "PEM encoded admin key file")
	cmd.MarkFlagsRequiredTogether("key", "cert")

	flags.String("pkcs11-config", "", "Path to a PKCS#11 configuration file to load the client certificate with")
	flags.String("pkcs11-key-id", "", "ID of the private key in the PKCS#11 token")
	flags.String("pkcs11-key-label", "", "Label of the private key in the PKCS#11 token")
	flags.String("pkcs11-cert-id", "", "ID of the certificate in the PKCS#11 token")
	flags.String("pkcs11-cert-label", "", "Label of the certificate in the PKCS#11 token")
	must(cobra.MarkFlagFilename(flags, "pkcs11-config", "json"))
	cmd.MarkFlagsOneRequired("pkcs11-key-id", "pkcs11-key-label", "cert")
	cmd.MarkFlagsOneRequired("pkcs11-cert-id", "pkcs11-cert-label", "cert")

	cmd.MarkFlagsMutuallyExclusive("pkcs11-config", "cert")
	cmd.MarkFlagsMutuallyExclusive("pkcs11-config", "key")
	cmd.MarkFlagsOneRequired("pkcs11-config", "cert")
	cmd.MarkFlagsOneRequired("pkcs11-config", "key")
}

// parseRestFlags parses the command line flags used to configure the REST client.
func parseRestFlags(cmd *cobra.Command) (api.VerifyOptions, string, error) {
	eraConfig, err := cmd.Flags().GetString("era-config")
	if err != nil {
		return api.VerifyOptions{}, "", err
	}
	insecure, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		return api.VerifyOptions{}, "", err
	}
	acceptedTCBStatuses, err := cmd.Flags().GetStringSlice("accepted-tcb-statuses")
	if err != nil {
		return api.VerifyOptions{}, "", err
	}
	acceptedAdvisories, err := cmd.Flags().GetStringSlice("accepted-advisories")
	if err != nil {
		return api.VerifyOptions{}, "", err
	}
	k8sNamespace, err := cmd.Flags().GetString("namespace")
	if err != nil {
		return api.VerifyOptions{}, "", err
	}
	nonce, err := cmd.Flags().GetString("nonce")
	if err != nil {
		return api.VerifyOptions{}, "", err
	}
	sgxQuotePath, err := cmd.Flags().GetString("save-sgx-quote")
	if err != nil {
		return api.VerifyOptions{}, "", err
	}

	if eraConfig == "" && !insecure {
		eraConfig = eraDefaultConfig

		// reuse existing config from current working directory if none specified
		// or try to get latest config from github if it does not exist
		if _, err := os.Stat(eraConfig); err == nil {
			fmt.Fprintln(cmd.OutOrStdout(), "Reusing existing config file")
		} else if err := fetchLatestCoordinatorConfiguration(cmd.Context(), cmd.OutOrStdout(), k8sNamespace); err != nil {
			return api.VerifyOptions{}, "", err
		}
	}

	var verifyOptions api.VerifyOptions

	if insecure {
		fmt.Fprintln(cmd.OutOrStdout(), "Warning: skipping quote verification")
		verifyOptions.InsecureSkipVerify = insecure
	} else {
		verifyOptions, err = api.VerifyOptionsFromConfig(eraConfig)
		if err != nil {
			return api.VerifyOptions{}, "", fmt.Errorf("reading era config file: %w", err)
		}
	}
	verifyOptions.AcceptedTCBStatuses = acceptedTCBStatuses
	verifyOptions.AcceptedAdvisories = acceptedAdvisories
	verifyOptions.Nonce = []byte(nonce)

	return verifyOptions, sgxQuotePath, nil
}

func fetchLatestCoordinatorConfiguration(ctx context.Context, out io.Writer, k8sNamespace string) error {
	coordinatorVersion, err := kube.CoordinatorVersion(ctx, k8sNamespace)
	eraURL := fmt.Sprintf("https://github.com/edgelesssys/marblerun/releases/download/%s/coordinator-era.json", coordinatorVersion)
	if err != nil {
		// if errors were caused by an empty kube config file or by being unable to connect to a cluster we assume the Coordinator is running as a standalone
		// and we default to the latest era-config file
		var dnsError *net.DNSError
		if !clientcmd.IsEmptyConfig(err) && !errors.As(err, &dnsError) && !os.IsNotExist(err) {
			return err
		}
		eraURL = "https://github.com/edgelesssys/marblerun/releases/latest/download/coordinator-era.json"
	}

	fmt.Fprintf(out, "No era config file specified, getting config from %s\n", eraURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, eraURL, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading era config for version %s: %w", coordinatorVersion, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading era config for version: %s: %d: %s", coordinatorVersion, resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	era, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("downloading era config for version %s: %w", coordinatorVersion, err)
	}

	if err := os.WriteFile(eraDefaultConfig, era, 0o644); err != nil {
		return fmt.Errorf("writing era config file: %w", err)
	}

	if coordinatorVersion != "" {
		fmt.Fprintf(out, "Got era config for version %s\n", coordinatorVersion)
	} else {
		fmt.Fprintln(out, "Got latest era config")
	}
	return nil
}

func checkLegacyKubernetesVersion(kubeClient kubernetes.Interface) (bool, error) {
	serverVersion, err := kubeClient.Discovery().ServerVersion()
	if err != nil {
		return false, err
	}
	versionInfo, err := version.ParseGeneric(serverVersion.String())
	if err != nil {
		return false, err
	}

	// return the legacy if kubernetes version is < 1.19
	if versionInfo.Major() == 1 && versionInfo.Minor() < 19 {
		return true, nil
	}

	return false, nil
}

func saveSgxQuote(fs afero.Fs, quote []byte, path string) error {
	if path == "" {
		return nil
	}
	return file.New(path, fs).Write(quote, file.OptOverwrite)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
