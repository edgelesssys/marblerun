// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package constants

const (
	// EnvMarbleTTLSConfig is the name of the environment variable used to pass the TTLS configuration to the Marble.
	EnvMarbleTTLSConfig = "MARBLE_TTLS_CONFIG"

	// MarbleEnvironmentCertificateChain contains the name of the environment variable holding a marble-specifc PEM encoded certificate.
	MarbleEnvironmentCertificateChain = "MARBLE_PREDEFINED_MARBLE_CERTIFICATE_CHAIN"

	// MarbleEnvironmentCoordinatorRootCA contains the name of the environment variable holding a PEM encoded root certificate.
	MarbleEnvironmentCoordinatorRootCA = "MARBLE_PREDEFINED_COORDINATOR_ROOT_CA"

	// MarbleEnvironmentPrivateKey contains the name of the environment variable holding a PEM encoded private key belonging to the marble-specific certificate.
	MarbleEnvironmentPrivateKey = "MARBLE_PREDEFINED_PRIVATE_KEY"
)
