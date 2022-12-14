# State and recovery

Persistent storage for confidential applications in the cloud requires a bit of attention.
If an application should be able to restart without manual intervention, it needs a way to automatically and securely obtain a secret to decrypt its state.

The SGX programming model considers a single, local application running on a specific CPU.
In this case, the application can use the SGX seal key as its root secret.
However, this binds the application and its state to the physical machine because seal keys are unique to a single CPU.
In sum, this means that the usual SGX programming model isn't suited for virtual environments or distributed applications.

With MarbleRun, the Coordinator [manages the Marbles' secrets](../features/secrets-management.md) and Marbles obtain them securely on start.
Thus, Marbles can be distributed and rescheduled on arbitrary machines.

Still, the Coordinator itself must keep its state persistent somehow. When being pinned to a single host the default SGX sealing methods are used. However, when the Coordinator is moved to another physical host, a manual step is required to ensure the Coordinator's state can be recovered.
Therefore, the manifest allows for specifying a designated *Recovery Key*. The Recovery Key is a public RSA key. Upon startup, the Coordinator encrypts its symmetric state-encryption key with this public key. The holder of the corresponding private key can recover the Coordinator, as is described [in the recovery workflow](../workflows/recover-coordinator.md).

:::caution

The owner of the Recovery Key can access the raw state of the Coordinator.

:::

<!--
## Distributed Coordinators with external store

<enterpriseBanner/>
-->

## Multi-party recovery

<enterpriseBanner/>

Depending on the use case, it may not be acceptable that the owner has full control over the cluster.
MarbleRun supports splitting the Recovery Key between parties.
Only if all parties agree can they recover a cluster or access the raw state.
