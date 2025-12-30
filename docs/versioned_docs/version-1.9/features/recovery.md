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
The instances share a common state, encrypted and stored as a Kubernetes secret.
The encryption key is securely distributed among the Coordinator instances via attested TLS.
Additionally, each Coordinator encrypts the encryption key with its SGX seal key and stores it in a ConfigMap.

In this mode of operation, manual recovery is only required when

* all Coordinator instances are stopped at the same time, and
* all new instances are scheduled on new physical hosts.
In other words, if at least one instance is scheduled on a host where a previous instance was running, the state can be recovered automatically.

## Recovery

The manifest allows for specifying a designated *Recovery Key*. The Recovery Key is a public RSA key. Upon startup, the Coordinator encrypts its symmetric state-encryption key with this public key. The holder of the corresponding private key can recover the Coordinator, as is described [in the recovery workflow](../workflows/recover-coordinator.md).

:::caution

The Recovery Key's owner can access the Coordinator's raw state.

:::

### Multi-party recovery

Depending on the use case, it may not be acceptable that the owner has full control over the cluster.
MarbleRun supports splitting the Recovery Key between parties.
Only if all parties agree can they recover a cluster or access the raw state.
