# Updating a deployment

The following gives a walkthrough of typical deployment updates in a Kubernetes cluster and how to handle them with MarbleRun.

## Before updating

Read the [release notes](https://github.com/edgelesssys/marblerun/releases) and check for any potential breaking changes affecting your deployment.

Make sure to [create a backup](./backup.md) of your current deployment before proceeding.

## Updating to a new MarbleRun version

When updating to a new MarbleRun version, updates to both the control plane and data plane components may be required.

### Updating the Coordinator

Get the latest chart information from the edgeless Helm repository:

```bash
helm repo update edgeless
```

Alternatively, you can get the chart directly from [GitHub](https://github.com/edgelesssys/marblerun/tree/master/charts).

Use `helm upgrade` to update your deployment. Note that Helm requires you to pass all the flags with `upgrade` that you set during the initial deployment.

```bash
VERSION=v1.X.X
helm upgrade marblerun edgeless/marblerun -n marblerun --version ${VERSION}
```

:::caution

If you've deployed only [one Coordinator instance](../features/recovery.md#single-coordinator) and it gets rescheduled to another node during the updating process, you need to perform the [recovery step](../features/recovery.md).

:::

The Marbles won't be affected by the Coordinator update and will continue running.
New Marbles that are started can interact with existing ones.
If the Coordinator version update also affects the data plane or the Marble bootstrapping process, you will need to restart your Marbles.

```bash
kubectl rollout restart deployment your_deployment_name
```

:::info

Updating the Coordinator image will change its `UniqueID`, but typically not its `SignerID`.

:::

### Updating Marbles

The tight integration of MarbleRun's data plane with your application requires a rebuild of your application and the corresponding containers.
Note that you only need to update if there have been changes affecting the data plane.
The process is similar to a regular update of your application, as is described in the following.

## Updating your confidential application

Updating your application is straightforward with MarbleRun.
You can roll out the new version similar to a regular [deployment update](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#updating-a-deployment).
The Coordinator will manage the attestation and bootstrapping of your new version.
Notably, nothing changes on the client-side of MarbleRun, the version update is transparent and adherent to the manifest in effect.
