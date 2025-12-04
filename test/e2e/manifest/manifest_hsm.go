//go:build hsmsealing

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package manifest

// DefaultManifest returns a manifest using the given user certificate and key.
func DefaultManifest(userCertPEM []byte, recoveryKeyPEM []byte, defaultPackage PackageProperties) Manifest {
	mnf := defaultManifest(userCertPEM, recoveryKeyPEM, defaultPackage)
	mnf.Config.FeatureGates = append(mnf.Config.FeatureGates, "AzureHSMSealing")
	return mnf
}
