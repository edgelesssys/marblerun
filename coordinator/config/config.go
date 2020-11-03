// Package config defines the environment variables expected by the Coordinator for configuration settings.
package config

// MeshAddr is the coordinator's address for the gRPC server to listen on
const MeshAddr = "EDG_COORDINATOR_MESH_ADDR"

// ClientAddr is the coordinator's address for the HTTP-REST server to listen on
const ClientAddr = "EDG_COORDINATOR_CLIENT_ADDR"

// DNSNames are the alternative dns names for the coordinator's certificate
const DNSNames = "EDG_COORDINATOR_DNS_NAMES"

// SealDir is the coordinator's file location to store the sealed state
const SealDir = "EDG_COORDINATOR_SEAL_DIR"

// DevMode enables more verbose logging
const DevMode = "EDG_COORDINATOR_DEV_MODE"
