// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package config defines the environment variables expected by the Marble for configuration settings.
package config

import (
	"path/filepath"

	"github.com/edgelesssys/marblerun/util"
)

// CoordinatorAddr is the marble's addr to connect to the coordinator via gRPC.
const CoordinatorAddr = "EDG_MARBLE_COORDINATOR_ADDR"

// CoordinatorAddrDefault is the marble's default addr to connect to the coordinator via gRPC.
const CoordinatorAddrDefault = "localhost:2001"

// Type is the marble's type used for attestation with the coordinator.
const Type = "EDG_MARBLE_TYPE"

// DNSNames are the alternative dns names for the marble's certificate.
const DNSNames = "EDG_MARBLE_DNS_NAMES"

// DNSNamesDefault are the default alternative dns names for the marble's certificate.
const DNSNamesDefault = "localhost"

// UUIDFile is the file path to store the marble's uuid.
const UUIDFile = "EDG_MARBLE_UUID_FILE"

// UUIDFileDefault is the default file path to store the marble's uuid.
func UUIDFileDefault() string { return filepath.Join(util.MustGetwd(), "uuid") }
