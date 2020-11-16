# Deployment Updates

This article should give you a walkthrough of typical deployment updates in a kubernetes cluster and how to handle them with Marblerun.

## Update to a new Marblerun version

From time to time we will release new features for Marblerun that you might want to have in your cluster.
When updating to a new Marblerun version you'll need to update the control plane and data plane components.
In some cases it might be sufficient to update only one of the two, we will highlight this accordingly in the release description.

### Updating Marblerun Coordinator

Updating the coordinator follows the regular steps for [updating a deployment in kubernetes](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#updating-a-deployment).

```bash
kubectl -n marblerun set image deployment/marblerun-coordinator coordinator=ghcr.io/edgelesssys/coordinator:v0.2.0 --record
```

You can also use helm to upgrade the image. Note that helm upgrade requires you to pass all the flags with `upgrade` that you set during the initial deployment.

```bash
helm upgrade marblerun-coordinator edgeless/marblerun-coordinator \
    -n marblerun \
    --set coordinator.coordinatorImageVersion=v0.2.0
```

If the coordinator is rescheduled on the same node it will continue running with the same manifest that has been in effect.
However, if the coordinator gets rescheduled to another node during the updating process you need to perform a simple [recovery step](recovery.md).

The marbles won't be affected by the coordinator update and will continue running.
New marbles that are started interact with the existing ones without any problems.
If the coordinator version update also affects the data plane or the marble bootstrapping process you will need to restart your marbles:

```bash
kubectl rollout restart deployment your_deployment_name
```

**Note** if you update the coordinator image you need to be careful about your client's configuration.
If you specified a `UniqueID` your clients won't accept the new coordinator version.
See our [remarks on manifest values](#manifest-values) for more information.

### Updating Marbles

The tight integration of Marblerun's data plane with your application requires a rebuild of your application and the containers.
Note that you only need to update if there have been changes affecting the data plane.
The process is similar to a regular update of your application, as described in the following section.

## Update your confidential application

Updating your application is straight forward with Marblerun.
You can roll out the new version similar to a regular [deployment update]((https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#updating-a-deployment)).
The coordinator will manage the attestation and bootstrapping of your new version.
Notably, nothing changes on the client-side of Marblerun, the version update is entirely transparent and adherent to the manifest in effect.

### Manifest values

Making updates work seamlessly requires some attention on what values are defined for your application in the manifest.
Take the following manifest as an example:

```json
"package": {
    "UniqueID": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "SignerID": "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffee",
    "ProductID": 1337,
    "SecurityVersion": 1,
    "Debug": false
}
```

If you set `UniqueID` you'll pin your application to one specific release build.
It will not be possible to update this release in the future.
We recommend setting the triple of `SignerID`, `ProductID`, and `SecurityVersion` instead.
`SignerID` will only accept releases signed by you.
`ProductID` will pin this package to one specific application and `SecuritVersion` to a minimum security version.
You define those values when building your application's secure enclave.
In the future, we are planning to support SecurityVersion updates in the manifest, making it possible to drop older potentially vulnerable versions of your software without redeploying a manifest.