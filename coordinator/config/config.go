// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package config defines the environment variables expected by the Coordinator for configuration settings.
package config

import (
	"path/filepath"

	"github.com/edgelesssys/marblerun/util"
)

// MeshAddr is the coordinator's address for the gRPC server to listen on.
const MeshAddr = "EDG_COORDINATOR_MESH_ADDR"

// MeshAddrDefault is the coordinator's default address for the gRPC server to listen on.
const MeshAddrDefault = ":2001"

// ClientAddr is the coordinator's address for the HTTP-REST server to listen on.
const ClientAddr = "EDG_COORDINATOR_CLIENT_ADDR"

// ClientAddrDefault is the coordinator's default address for the HTTP-REST server to listen on.
const ClientAddrDefault = ":4433"

// PromAddr is the coordinator's address for the prometheus endpoint server to listen on.
const PromAddr = "EDG_COORDINATOR_PROMETHEUS_ADDR"

// DNSNames are the alternative dns names for the coordinator's certificate.
const DNSNames = "EDG_COORDINATOR_DNS_NAMES"

// DNSNamesDefault are the default dns names for the coordinator's certificate.
const DNSNamesDefault = "localhost"

// SealDir is the coordinator's file location to store the sealed state.
const SealDir = "EDG_COORDINATOR_SEAL_DIR"

// SealDirDefault returns the coordinator's default file location to store the sealed state.
func SealDirDefault() string { return filepath.Join(util.MustGetwd(), "marblerun-coordinator-data") }

// DevMode enables more verbose logging.
const DevMode = "EDG_COORDINATOR_DEV_MODE"

// DevModeDefault is the default logging mode.
const DevModeDefault = "0"

/// StartupManifest is a path to a manifest to start with instead of waiting for a manifest from the api
const StartupManifest = "EDG_STARTUP_MANIFEST"
