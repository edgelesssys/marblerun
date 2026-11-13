# State and recovery

Persistent storage for confidential applications in the cloud requires attention.
If an application should be able to restart without manual intervention, it needs a way to automatically and securely obtain a secret to decrypt its state.

The SGX programming model considers a single, local application running on a specific CPU.
The application can use the SGX seal key as its root secret.
However, this binds the application and its state to the physical machine because seal keys are unique to a single CPU.
In sum, the usual SGX programming model isn't suited for virtual environments or distributed applications.

With MarbleRun, the Coordinator [manages the Marbles' secrets](../features/secrets-management.md), and Marbles obtain them securely on start.
Thus, Marbles can be distributed and rescheduled on arbitrary machines.
This narrows the challenge of persistent storage down to the Coordinator itself.

### Single Coordinator

The straightforward way to run MarbleRun is with a single Coordinator.
In this case, the state is encrypted with the SGX seal key and stored on disk.
When pinned to a single host, the Coordinator can unseal its state automatically.
However, a [manual step](#recovery) is required to recover the Coordinator's state when the Coordinator is moved to another physical host.

### Distributed Coordinator

When you use MarbleRun [with Kubernetes](../deployment/kubernetes.md), you can scale the Coordinator to multiple instances.
The instances share a common state, encrypted and stored in Kubernetes Secrets.
The encryption key is securely distributed among the Coordinator instances via attested TLS.
Additionally, each Coordinator encrypts the encryption key with its SGX seal key and stores it in a ConfigMap.

In this mode of operation, manual recovery is only required when

* all Coordinator instances are stopped at the same time, and
* all new instances are scheduled on new physical hosts.
In other words, if at least one instance is scheduled on a host where a previous instance was running, the state can be recovered automatically.

### State larger than one Secret

The distributed Kubernetes store initially keeps the sealed state and wrapped encryption key in the existing state Secret (`marblerun-state` by default).
After chunking is enabled, a write that exceeds Kubernetes' 1 MiB Secret data limit automatically migrates the state to immutable 512 KiB chunk Secrets.
The original Secret becomes a small head containing the chunk descriptor and matching wrapped key.
The head update atomically publishes the entire snapshot; conflicting writers fail rather than overwrite newer state.
Migration is one-way: shrinking the state does not return it to inline storage.
The current implementation limits sealed state to 16 MiB, and the wrapped key plus head descriptor must still fit in one Secret.

For existing deployments, enable chunking in two stages:

1. Upgrade **all** Coordinator replicas to a version supporting chunked state, keeping `coordinator.chunkedState: false` in the Helm values. The chart also grants the Secret `list` and `delete` permissions needed for cleanup.
2. After the rollout completes and no legacy instances can write, set `coordinator.chunkedState: true`. The equivalent environment variable is `EDG_K8S_CHUNKED_STATE=true`. No state export/import is needed.

Do not enable chunking during a rolling upgrade that still contains old binaries.
Disabling the setting later prevents only the first migration; already chunked state remains readable and writable.
Downgrading to a binary without chunk support is unsupported after migration.
Before migration, writes that exceed the Secret limit with chunking disabled return a capacity error and leave the committed state unchanged.

#### Revisions and cleanup

Legacy state starts at revision 0. Every successful state save advances the revision, including inline saves and recovery writes.
Chunks carry `marblerun.edgeless.systems/state-revision` and a unique upload ID, so concurrent attempts at the same revision cannot mix their data.
GC-only updates do not advance the logical revision.

On storage operations, each replica normally attempts cleanup once every five minutes, with a 20-second budget and at most 64 candidate chunks per batch.
The budget accommodates a full batch at Kubernetes client-go's default rate limit of five requests per second.
After a full batch or an error, cleanup is eligible again after ten seconds, on the next storage operation.
Cleanup is synchronous and respects the caller's deadline, so an operation that triggers it can incur up to 20 seconds of additional latency.
Chunks younger than ten minutes are retained. Current chunks are always retained regardless of age.
Cleanup first selects candidates and then updates a barrier annotation on the head using Kubernetes `resourceVersion`, fencing incomplete writers before deletion.
Readers retry if their snapshot was superseded and collected. Cleanup failures are logged and do not turn a successful state save into an error.
Failed first migrations are also cleaned up while chunking is enabled, even if the head is still inline.
Fully idle deployments can retain unused chunks until the next operation.

The Coordinator needs namespace-level Secret `get`, `create`, `update`, `list`, and `delete` permissions.
Kubernetes RBAC cannot restrict these dynamic chunk names by label; consider this access when choosing a namespace.
Deleting the head also makes its chunks eligible for Kubernetes owner-reference garbage collection.

When Prometheus is enabled, monitor `coordinator_state_bytes`, `coordinator_state_revision`, `coordinator_state_gc_candidates`, `coordinator_state_gc_errors_total`, and `coordinator_state_gc_duration_seconds`.
The candidate gauge describes the last bounded batch, not the total orphan count.
Allow Secret-count and etcd capacity headroom for the current snapshot, concurrent uploads, and retained older revisions.
Each commit still rewrites the complete state; chunking removes the single-Secret limit, not API-server or memory limits.

## Recovery

The manifest allows for specifying a designated *Recovery Key*. The Recovery Key is a public RSA key. Upon startup, the Coordinator encrypts its symmetric state-encryption key with this public key. The holder of the corresponding private key can recover the Coordinator, as is described [in the recovery workflow](../workflows/recover-coordinator.md).

:::caution

The Recovery Key's owner can access the Coordinator's raw state.

:::

### Multi-party recovery

Depending on the use case, it may not be acceptable that the owner has full control over the cluster.
MarbleRun supports splitting the Recovery Key between parties.
Only if all parties agree can they recover a cluster or access the raw state.
