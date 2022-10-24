# Updating a deployment

The following gives a walkthrough of typical deployment updates in a Kubernetes cluster and how to handle them with MarbleRun.

## Updating to a new MarbleRun version

When updating to a new MarbleRun version, updates to both the control plane and data plane components may be required.

### Updating the Coordinator

Updating the Coordinator follows the regular steps for [updating a deployment in Kubernetes](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#updating-a-deployment).

```bash
kubectl -n marblerun set image deployment/marblerun-coordinator coordinator=ghcr.io/edgelesssys/coordinator:latest --record
```

You can also use Helm to upgrade the image. Note that Helm requires you to pass all the flags with `upgrade` that you set during the initial deployment.

```bash
helm upgrade marblerun edgeless/marblerun \
    -n marblerun \
    --set coordinator.coordinatorImageVersion=latest
```

If the Coordinator is rescheduled on the same host as before, it will continue running with the same manifest as before.
However, if the Coordinator gets rescheduled to another node during the updating process you need to perform the [recovery step](features/recovery.md).

The Marbles won't be affected by the Coordinator update and will continue running.
New Marbles that are started can interact with existing ones.
If the Coordinator version update also affects the data plane or the Marble bootstrapping process, you will need to restart your Marbles.

```bash
kubectl rollout restart deployment your_deployment_name
```

?> Updating the Coordinator image will change its `UniqueID`, but typically not its `SignerID`.

### Updating Marbles

The tight integration of MarbleRun's data plane with your application requires a rebuild of your application and the corresponding containers.
Note that you only need to update if there have been changes affecting the data plane.
The process is similar to a regular update of your application, as is described in the following.

## Updating your confidential application

Updating your application is straightforward with MarbleRun.
You can roll out the new version similar to a regular [deployment update](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#updating-a-deployment).
The Coordinator will manage the attestation and bootstrapping of your new version.
Notably, nothing changes on the client-side of MarbleRun, the version update is transparent and adherent to the manifest in effect.
