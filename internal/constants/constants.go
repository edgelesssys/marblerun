/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package constants

const (
	// EnvLogFormat is the name of the environment variable used to pass the log format to the PreMain.
	// Should be "json" for JSON formatted logs, or any other value for human-readable logs.
	EnvLogFormat = "EDG_LOG_FORMAT"
	// LogFormatJSON indicates that logs should be formatted as JSON.
	LogFormatJSON = "json"

	// EnvMarbleTTLSConfig is the name of the environment variable used to pass the TTLS configuration to the Marble.
	EnvMarbleTTLSConfig = "MARBLE_TTLS_CONFIG"

	// MarbleEnvironmentCertificateChain contains the name of the environment variable holding a marble-specifc PEM encoded certificate.
	MarbleEnvironmentCertificateChain = "MARBLE_PREDEFINED_MARBLE_CERTIFICATE_CHAIN"

	// MarbleEnvironmentCoordinatorRootCA contains the name of the environment variable holding a PEM encoded root certificate.
	MarbleEnvironmentCoordinatorRootCA = "MARBLE_PREDEFINED_COORDINATOR_ROOT_CA"

	// MarbleEnvironmentPrivateKey contains the name of the environment variable holding a PEM encoded private key belonging to the marble-specific certificate.
	MarbleEnvironmentPrivateKey = "MARBLE_PREDEFINED_PRIVATE_KEY"
)
