/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// Package helm provides functions to install and uninstall the MarbleRun Helm chart.
package helm

// Helm constants.
const (
	CoordinatorDeployment = "marblerun-coordinator"
	InjectorDeployment    = "marble-injector"
	Namespace             = "marblerun"
	chartName             = "edgeless/marblerun"
	release               = "marblerun"
	repoURI               = "https://helm.edgeless.systems/stable"
	repoName              = "edgeless"
)
