# Coordinator

The Coordinator is MarbleRun's control plane.
Conceptionally it operators as trusted controller in your confidential deployment.
Therefore, it securely holds the deployment's state in form of the [manifest](../features/manifest.md) and the defined [secrets](../features/secrets-management.md).
Based on the manifest, the Coordinator uses [remote attestation](../features/attestation.md) to authenticate the application's enclaves.



## API and Configuration

It communicates with the Marble's data plane through gRPC and provides an HTTP REST interface on the client-side.
The Coordinator can be configured with several environment variables:

* `EDG_COORDINATOR_MESH_ADDR`: The listener address for the gRPC server
* `EDG_COORDINATOR_CLIENT_ADDR`: The listener address for the HTTP REST server
* `EDG_COORDINATOR_DNS_NAMES`: The DNS names for the cluster's root certificate
* `EDG_COORDINATOR_SEAL_DIR`: The file path for storing sealed data

When you use MarbleRun [with Kubernetes](../deployment/kubernetes.md), you can [scale the Coordinator to multiple instances](../features/recovery.md#distributed-coordinator) to increase availability and reduce the occurrence of events that require [manual recovery](../workflows/recover-coordinator.md).

The Coordinator clients can be divided into two major groups.

* The owners/providers/administrators who need to interact with the Coordinator for deploying their confidential application and administrative tasks
* The users/customers who use the Coordinator for remote attestation and establishing trust with the application

The [Client API](../reference/coordinator.md) serves both use-cases with a compact HTTP REST API.
