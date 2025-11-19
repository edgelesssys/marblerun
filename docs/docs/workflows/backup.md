# Backing up and restoring MarbleRun state

In a production environment, you should regularly back up the state of the MarbleRun Coordinator to be able to restore it in case of failure. Backup is easy, but there are differences based on how you deployed MarbleRun.

## Prerequisites

Restoring a backup includes [recovering the Coordinator](../features/recovery.md), so you need to [define recovery keys](define-manifest.md#recoverykeys) in the manifest.

## Backing up the Coordinator state

The Coordinator supports live backup, so you can back up its state without stopping it.

<Tabs groupId="deployment">
<TabItem value="distributed" label="Kubernetes, distributed Coordinator">

Make a copy of the `marblerun-state` Secret in the `marblerun` namespace:

```bash
kubectl -n marblerun get secret marblerun-state -o yaml > marblerun-state-backup.yaml
```

</TabItem>
<TabItem value="single" label="Kubernetes, single Coordinator">

The state is stored on a PersistentVolume bound to the PersistentVolumeClaim `coordinator-pv-claim` in the `marblerun` namespace.
Check the documentation of your Kubernetes distribution on the available options to back up PersistentVolumes.

Alternatively, you can copy the `sealed_data` file from the PersistentVolume (via the Coordinator Pod) to your machine:

```bash
podname=$(kubectl -n marblerun get pods -l app.kubernetes.io/name=coordinator -o jsonpath='{.items[0].metadata.name}')
kubectl -n marblerun cp $podname:/coordinator/data/sealed_data sealed_data_backup
```

</TabItem>
<TabItem value="standalone" label="Standalone">

Make a copy of the `sealed_data` file in the `marblerun-coordinator-data` directory.

</TabItem>
</Tabs>

## Restoring the Coordinator state

<Tabs groupId="deployment">
<TabItem value="distributed" label="Kubernetes, distributed Coordinator">

1. Stop all Coordinator instances:

   ```bash
   kubectl -n marblerun scale --replicas=0 deployment/marblerun-coordinator
   ```

2. Apply the state from the backup:

   ```bash
   kubectl apply -f marblerun-state-backup.yaml
   ```

3. Scale the Coordinator back to the desired number of instances:

   ```bash
   kubectl -n marblerun scale --replicas=3 deployment/marblerun-coordinator
   ```

:::tip

If you want to restore MarbleRun in a fresh cluster, you can apply the state from the backup before installing MarbleRun:

```bash
kubectl create ns marblerun
kubectl apply -f marblerun-state-backup.yaml
marblerun install ...
```

:::

</TabItem>
<TabItem value="single" label="Kubernetes, single Coordinator">

* If you have a backup of the PersistentVolume, stop the Coordinator instance, restore the volume, and start the Coordinator again.
* If you have a backup of the `sealed_data` file, copy it to the PersistentVolume and then restart the Coordinator:

  ```bash
  podname=$(kubectl -n marblerun get pods -l app.kubernetes.io/name=coordinator -o jsonpath='{.items[0].metadata.name}')
  kubectl -n marblerun cp sealed_data_backup $podname:/coordinator/data/sealed_data
  kubectl -n marblerun delete pod $podname
  ```

</TabItem>
<TabItem value="standalone" label="Standalone">

Stop the Coordinator, copy back the `sealed_data` file to the `marblerun-coordinator-data` directory, and start the Coordinator again.

</TabItem>
</Tabs>

After restoring the state from the backup, you may need to [recover the Coordinator](recover-coordinator.md).

## Things to consider

**Backup events**: In addition to regular backups, you may want to back up the state after significant changes, such as manifest updates.

**Cluster backup**: If you use a Kubernetes cluster backup solution, the MarbleRun state may already be included in that backup. You should check if restoring and recovering the Coordinator works as expected.

**Marbles**: Marbles may have state and that state may depend on the Coordinator state (e.g., secrets, monotonic counters). If so, you may need to back up Marble state and Coordinator state together.
