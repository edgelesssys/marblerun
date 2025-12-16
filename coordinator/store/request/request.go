/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// request defines constants used to access the store.
package request

// Available store keys.
const (
	Activations       = "activations"
	Certificate       = "certificate"
	Infrastructure    = "infrastructure"
	Manifest          = "manifest"
	ManifestSignature = "manifestSignature"
	Marble            = "marble"
	MonotonicCounter  = "monotonicCounter"
	Package           = "package"
	PrivateKey        = "privateKey"
	Secret            = "secret"
	PreviousSecret    = "previousSecret"
	State             = "state"
	TLS               = "TLS"
	User              = "user"
	UpdateLog         = "updateLog"
)
