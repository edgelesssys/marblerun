// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package cmd implements the MarbleRun's CLI commands.
package cmd

import (
	"context"
	"io"

	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/spf13/afero"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/client-go/kubernetes"
)

func webhookDNSName(namespace string) string {
	return "marble-injector." + namespace
}

type getter interface {
	Get(ctx context.Context, path string, body io.Reader, queryParameters ...string) ([]byte, error)
}

type poster interface {
	Post(ctx context.Context, path, contentType string, body io.Reader) ([]byte, error)
}

// restFlags are command line flags used to configure the REST client to talk to the Coordinator.
type restFlags struct {
	// k8sNamespace is the namespace of the MarbleRun installation.
	// We use this to try to find the Coordinator when retrieving the era config.
	k8sNamespace string
	// eraConfig is the path to the era config file.
	eraConfig string
	// insecure is a flag to disable TLS verification.
	insecure bool
	// acceptedTCBStatuses is a list of TCB statuses that are accepted by the CLI.
	// This can be used to allow connections to Coordinator instances running on outdated hardware or firmware.
	acceptedTCBStatuses []string
	// nonce is a user supplied nonce to be used in the attestation process.
	nonce []byte
}

// parseRestFlags parses the command line flags used to configure the REST client.
func parseRestFlags(flags *pflag.FlagSet) (restFlags, error) {
	eraConfig, err := flags.GetString("era-config")
	if err != nil {
		return restFlags{}, err
	}
	insecure, err := flags.GetBool("insecure")
	if err != nil {
		return restFlags{}, err
	}
	acceptedTCBStatuses, err := flags.GetStringSlice("accepted-tcb-statuses")
	if err != nil {
		return restFlags{}, err
	}
	k8snamespace, err := flags.GetString("namespace")
	if err != nil {
		return restFlags{}, err
	}
	nonce, err := flags.GetString("nonce")
	if err != nil {
		return restFlags{}, err
	}

	return restFlags{
		k8sNamespace:        k8snamespace,
		eraConfig:           eraConfig,
		insecure:            insecure,
		acceptedTCBStatuses: acceptedTCBStatuses,
		nonce:               []byte(nonce),
	}, nil
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

func newMutualAuthClient(hostname string, flags *pflag.FlagSet, fs afero.Fs) (*rest.Client, error) {
	insecureTLS, err := flags.GetBool("insecure")
	if err != nil {
		return nil, err
	}

	caCert, err := rest.LoadCoordinatorCachedCert(flags, fs)
	if err != nil {
		return nil, err
	}
	clientCert, err := rest.LoadClientCert(flags)
	if err != nil {
		return nil, err
	}

	return rest.NewClient(hostname, caCert, clientCert, insecureTLS)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
