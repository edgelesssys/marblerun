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

	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/client-go/kubernetes"
)

const webhookName = "marble-injector.marblerun"

type getter interface {
	Get(ctx context.Context, path string, body io.Reader, queryParameters ...string) ([]byte, error)
}

type poster interface {
	Post(ctx context.Context, path, contentType string, body io.Reader) ([]byte, error)
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

func must(err error) {
	if err != nil {
		panic(err)
	}
}
