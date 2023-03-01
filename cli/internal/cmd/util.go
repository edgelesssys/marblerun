// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/client-go/kubernetes"
)

const webhookName = "marble-injector.marblerun"

const promptForChanges = "Do you want to automatically apply the suggested changes [y/n]? "

func promptYesNo(stdin io.Reader, question string) (bool, error) {
	fmt.Print(question)
	reader := bufio.NewReader(stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	response = strings.ToLower(strings.TrimSpace(response))

	if response != "y" && response != "yes" {
		return false, nil
	}

	return true, nil
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
