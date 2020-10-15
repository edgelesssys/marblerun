// Package config defines the environment variables expected by the Coordinator for configuration settings.
package config

// EdgMeshServerAddr is the coordinator's address for the gRPC server to listen on
const EdgMeshServerAddr string = "EDG_MESH_SERVER_ADDR"

// EdgClientServerAddr is the coordinator's address for the HTTP-REST server to listen on
const EdgClientServerAddr string = "EDG_CLIENT_SERVER_ADDR"

// EdgCoordinatorDNSNames are the alternative dns names for the coordinator's certificate
const EdgCoordinatorDNSNames string = "EDG_COORDINATOR_DNS_NAMES"

// EdgCoordinatorSealDir is the coordinator's file location to store the sealed state
const EdgCoordinatorSealDir string = "EDG_COORDINATOR_SEAL_DIR"
