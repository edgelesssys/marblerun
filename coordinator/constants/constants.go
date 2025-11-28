/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// constants defines constant values used in the Coordinator.
package constants

import (
	"path/filepath"

	"github.com/edgelesssys/marblerun/util"
)

const (
	// CoordinatorName is the name of the Coordinator.
	// It is used as CN of the root certificate.
	CoordinatorName = "MarbleRun Coordinator"
	// CoordinatorIntermediateName is the name of the Coordinator.
	// It is used as CN of the intermediate certificate which is set when setting or updating a certificate.
	CoordinatorIntermediateName = "MarbleRun Coordinator - Intermediate CA"

	// Storage Keys for the Coordinator's certificates,
	// used to reference the certificates in the store.

	// SKCoordinatorRootCert is the key for the Coordinator's root certificate.
	SKCoordinatorRootCert = "coordinatorRootCert"
	// SKCoordinatorRootKey is the key for private key corresponding to the Coordinator's root certificate.
	SKCoordinatorRootKey = "coordinatorRootKey"
	// SKCoordinatorIntermediateCert is the key for the Coordinator's intermediate certificate.
	SKCoordinatorIntermediateCert = "coordinatorIntermediateCert"
	// SKCoordinatorIntermediateKey is the key for private key corresponding to the Coordinator's root certificate.
	SKCoordinatorIntermediateKey = "coordinatorIntermediateKey"
	// SKMarbleRootCert is the key for the root certificate for Marble certificates.
	SKMarbleRootCert = "marbleRootCert"

	// MeshAddr is the coordinator's address for the gRPC server to listen on.
	MeshAddr = "EDG_COORDINATOR_MESH_ADDR"
	// MeshAddrDefault is the coordinator's default address for the gRPC server to listen on.
	MeshAddrDefault = ":2001"
	// ClientAddr is the coordinator's address for the HTTP-REST server to listen on.
	ClientAddr = "EDG_COORDINATOR_CLIENT_ADDR"
	// ClientAddrDefault is the coordinator's default address for the HTTP-REST server to listen on.
	ClientAddrDefault = ":4433"
	// PromAddr is the coordinator's address for the prometheus endpoint server to listen on.
	PromAddr = "EDG_COORDINATOR_PROMETHEUS_ADDR"

	// DNSNames are the alternative dns names for the coordinator's certificate.
	DNSNames = "EDG_COORDINATOR_DNS_NAMES"
	// DNSNamesDefault are the default dns names for the coordinator's certificate.
	DNSNamesDefault = "localhost"

	// SealDir is the coordinator's file location to store the sealed state.
	SealDir = "EDG_COORDINATOR_SEAL_DIR"

	// DevMode enables more verbose logging.
	DevMode = "EDG_COORDINATOR_DEV_MODE"
	// DevModeDefault is the default logging mode.
	DevModeDefault = "0"

	// DebugLogging enables debug logs.
	DebugLogging = "EDG_DEBUG_LOGGING"
	// DebugLoggingDefault is the default value to use when the [DebugLogging] env variable is not set.
	DebugLoggingDefault = "0"

	// StartupManifest is a path to a manifest to start with instead of waiting for a manifest from the api.
	StartupManifest = "EDG_STARTUP_MANIFEST"

	// EnvStoreBackend is the environment variable defining the store backend to use.
	EnvStoreBackend = "EDG_STORE_BACKEND"
	// EnvK8sStateName is the environment variable defining the name of the secret
	// holding the Coordinator's state.
	EnvK8sStateName = "EDG_K8S_STATE_NAME"
	// EnvK8sKeyServiceName is the environment variable defining the name of the MarblerRun key distribution service.
	EnvK8sKeyServiceName = "EDG_K8S_SERVICE_NAME"
	// EnvK8sKEKMapName is the environment variable defining the name of the ConfigMap holding the sealed KEKs.
	EnvK8sKEKMapName = "EDG_K8S_KEK_MAP"
	// EnvK8sDeploymentNamespace is the environment variable defining the namespace of the MarblerRun deployment.
	EnvK8sDeploymentNamespace = "EDG_K8S_NAMESPACE"
	// EnvFeatureGates is the environment variable defining the feature gates to enable.
	EnvFeatureGates = "EDG_ENTERPRISE_LICENSED_FEATURES"
	// EnvDistributedDeployment indicates whether the Coordinator is deployed in distributed mode.
	EnvDistributedDeployment = "EDG_DISTRIBUTED_COORDINATOR"

	// EnvKubernetesServiceHost is the environment variable defining the address of the API server.
	EnvKubernetesServiceHost = "KUBERNETES_SERVICE_HOST"
	// EnvKubernetesServicePort is the environment variable defining the port of the API server.
	EnvKubernetesServicePort = "KUBERNETES_SERVICE_PORT"

	// EnvHSMVaultURL holds the Azure Key Vault URL for Secure Key Release.
	EnvHSMVaultURL = "EDG_HSM_VAULT_URL"
	// EnvHSMKeyName holds the name of the key to use for Secure Key Release.
	EnvHSMKeyName = "EDG_HSM_KEY_NAME"
	// EnvHSMKeyVersion holds the version of the key to use for Secure Key Release.
	// If empty, the latest version is used.
	EnvHSMKeyVersion = "EDG_HSM_KEY_VERSION"
	// EnvMAAURL holds the MAA (Microsoft Attestation Agent) URL to use for retrieving an
	// attestation token to authenticate against the keyvault for Secure Key Release.
	EnvMAAURL = "EDG_MAA_URL"
	// EnvAzureClientID holds the Azure Client ID for authentication with the Azure SDK.
	EnvAzureClientID = "AZURE_CLIENT_ID"
	// EnvAzureTenantID holds the Azure Tenant ID for authentication with the Azure SDK.
	EnvAzureTenantID = "AZURE_TENANT_ID"
	// EnvAzureClientSecret holds the Azure Client Secret for authentication with the Azure SDK.
	EnvAzureClientSecret = "AZURE_CLIENT_SECRET"

	// StoreBackendKubernetes indicates that Kubernetes secrets should be used to hold
	// the Coordinator's state.
	StoreBackendKubernetes = "k8s-secret"

	// KeyDistributorPort is the port on which the key distributor listens.
	KeyDistributorPort = "5433"
)

// SealDirDefault returns the coordinator's default file location to store the sealed state.
func SealDirDefault() string { return filepath.Join(util.MustGetwd(), "marblerun-coordinator-data") }
