# Deployment updates

The following gives a walkthrough of typical deployment updates in a Kubernetes cluster and how to handle them with Marblerun.

## Updating to a new Marblerun version

When updating to a new Marblerun version, updates to both the control plane and data plane components may be required.

### Updating the Coordinator

Updating the Coordinator follows the regular steps for [updating a deployment in Kubernetes](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#updating-a-deployment).

```bash
kubectl -n marblerun set image deployment/marblerun-coordinator coordinator=ghcr.io/edgelesssys/coordinator:v0.2.0 --record
```

You can also use Helm to upgrade the image. Note that Helm requires you to pass all the flags with `upgrade` that you set during the initial deployment.

```bash
helm upgrade marblerun-coordinator edgeless/marblerun-coordinator \
    -n marblerun \
    --set coordinator.coordinatorImageVersion=v0.2.0
```

If the Coordinator is rescheduled on the same host as before, it will continue running with the same Manifest as before.
However, if the Coordinator gets rescheduled to another node during the updating process you need to perform the [recovery step](recovery.md).

The Marbles won't be affected by the Coordinator update and will continue running.
New Marbles that are started can interact with existing ones.
If the Coordinator version update also affects the data plane or the Marble bootstrapping process, you will need to restart your Marbles.

```bash
kubectl rollout restart deployment your_deployment_name
```

**Note:** when updating the Coordinator image, you need to be careful about your client's configuration.
If you specified a `UniqueID`, your clients won't accept the new Coordinator version.
See our [remarks on Manifest values](#manifest-values) for more information.

### Updating Marbles

The tight integration of Marblerun's data plane with your application requires a rebuild of your application and the corresponding containers.
Note that you only need to update if there have been changes affecting the data plane.
The process is similar to a regular update of your application, as is described in the following.

## Updating your confidential application

Updating your application is straightforward with Marblerun.
You can roll out the new version similar to a regular [deployment update]((https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#updating-a-deployment)).
The Coordinator will manage the attestation and bootstrapping of your new version.
Notably, nothing changes on the client-side of Marblerun, the version update is transparent and adherent to the Manifest in effect.

### Manifest values

Making updates work seamlessly requires some attention on what values are defined for your application in the Manifest.
Take the following Manifest as an example:

```json
"package": {
    "UniqueID": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "SignerID": "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffee",
    "ProductID": 42,
    "SecurityVersion": 1,
    "Debug": false
}
```

Setting `UniqueID` (aka `MRENCLAVE`), will pin your application to one specific release build.
It will not be possible to update this release in the future.
We recommend setting the triple of `SignerID`, `ProductID`, and `SecurityVersion` instead.
`SignerID` will only accept releases signed by you.
`ProductID` will pin this package to one specific application and `SecuritVersion` to a minimum security version.
You define those values when building your application's secure enclave.
Future versions of Marblerun will support `SecurityVersion` updates in the Manifest, making it possible to drop older potentially vulnerable versions of your software without redeploying a Manifest.