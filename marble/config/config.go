// Copyright (c) Edgeless Systems GmbH.
// Licensed under the MIT License.

// Package config defines the environment variables expected by the Marble for configuration settings.
package config

// CoordinatorAddr is the marble's addr to connect to the coordinator via gRPC
const CoordinatorAddr = "EDG_MARBLE_COORDINATOR_ADDR"

// Type is the marble's type used for attestation with the coordinator
const Type = "EDG_MARBLE_TYPE"

// DNSNames are the alternative dns names for the marble's certificate
const DNSNames = "EDG_MARBLE_DNS_NAMES"

// UUIDFile is the file path to store the marble's uuid
const UUIDFile = "EDG_MARBLE_UUID_FILE"
