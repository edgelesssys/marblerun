// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package helm provides functions to install and uninstall the MarbleRun Helm chart.
package helm

// Helm constants.
const (
	ChartName             = "edgeless/marblerun"
	ChartNameEnterprise   = "edgeless/marblerun-enterprise"
	CoordinatorDeployment = "marblerun-coordinator"
	InjectorDeployment    = "marble-injector"
	Namespace             = "marblerun"
	Release               = "marblerun"
	RepoURI               = "https://helm.edgeless.systems/stable"
	RepoName              = "edgeless"
)
