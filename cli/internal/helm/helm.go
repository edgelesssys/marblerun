// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package helm provides functions to install and uninstall the MarbleRun Helm chart.
package helm

// Helm constants.
const (
	CoordinatorDeployment = "marblerun-coordinator"
	InjectorDeployment    = "marble-injector"
	Namespace             = "marblerun"
	chartName             = "edgeless/marblerun"
	chartNameEnterprise   = "edgeless/marblerun-enterprise"
	release               = "marblerun"
	repoURI               = "https://helm.edgeless.systems/stable"
	repoName              = "edgeless"
)
